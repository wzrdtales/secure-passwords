'use strict';

const Promise = require('bluebird');
const crypto = require('crypto');
const moment = require('moment');

// an interesting way of putting the whole extra load onto the
// client. unlike other algos, we dont have to compute the result
// ourselves, we have a rather short and cheap validation
const pow = (input, domain, prior, rounds, responses, { challenge: { difficulty_factor: diff } }) => {
  const fin = crypto
    .createHash('sha512')
    .update(`${input.challenge}${input.date}${domain}${prior}`)
    .digest('hex');
  let i = 0;

  if (!Array.isArray(responses)) return null;

  while (i * 64 < fin.length) {
    const auth = responses[i];

    if (!auth) return null;

    const string = fin.substring(i * 64, i * 64 + 64);

    const prefix = Buffer.from([string.length, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);

    const hash = crypto.createHash('sha256').update(`${input.challenge}${prefix}${string}${auth.nonce}`).digest('hex');
    const p = BigInt(auth.result);
    if (!(hash.startsWith(p.toString(16)) && p > diff)) return null;
    ++i;
  }

  return responses;
};

const algos = { pow };
const extChallenge = {
  pow: function () {
    let difficultyFactor;
    if (this.extraOpts && this.extraOpts.challenge && this.extraOpts.challenge.diff) {
      difficultyFactor = this.extraOpts.challenge.diff;
    } else {
      difficultyFactor = 100000;
    }

    return {
      difficulty_factor: difficultyFactor
    };
  }
};

const decrypt = (input, key, iv) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  const decrypted = decipher.update(input, 'base64', 'utf8');
  return decrypted + decipher.final('utf8');
};

const processRounds = async (input, domain, prior, rounds) => {
  function hash (challenge, prior) {
    return crypto
      .createHash('sha512')
      .update(`${challenge.challenge}${challenge.date}${domain}${prior}`)
      .digest('hex');
  }

  // This should be optimized with process.nextTick
  // For now keep it simple but prepared
  return new Promise((resolve) => {
    while (rounds--) {
      prior = hash(input, prior);
    }
    resolve(prior);
  });
};
const randomString = function (len) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(Math.ceil(len / 2), (err, buf) => {
      if (err) {
        return reject(err);
      }

      resolve(buf.toString('hex').slice(0, len));
    });
  });
};

/**
 * This provides a secure authentication strategy.
 *
 * Any authentication request is bound to the requesters ip.
 * */
class SP {
  constructor (options = {}) {
    if (options.algorithm && (!typeof options.algorithm === 'function' || !algos[options.algorithm])) {
      throw new Error('Passed an invalid algorithm');
    }

    if (options.extChallenge && (!typeof options.extChallenge === 'function' || !extChallenge[options.extChallenge])) {
      throw new Error('Passed an invalid algorithm to extChallenge');
    }

    if (
      options.algorithm &&
      options.hashAlgorithm &&
      typeof options.hashAlgorithm !== 'string'
    ) {
      throw new Error('Expected a string for option hashAlgorithm');
    }

    if (!options.db && typeof options.db !== 'object') {
      throw new Error('Missing database controller');
    }

    if (!options.domain && typeof options.domain !== 'string') {
      throw new Error('Missing TLD name.');
    }

    this.algorithm = options.algorithm;
    this.extChallenge = (typeof options.extChallenge === 'function' ? options.extChallenge : extChallenge[options.extChallenge]) ||
      function () { return {}; };
    this.extraOpts = options.extraOpts;
    // this is what we tell the user
    this.hash = options.algorithm ? options.hashAlgorithm : 'sha512';
    this.db = options.db;
    this.rounds = options.rounds || 10;
    // The default of 10 seconds should be reasonable enough
    this.validTill = options.validTill || 10 * 1000;
    this.options = options;
    this.domain = options.domain;
    this.providesAge = options.providesAge || false;
  }

  async challenge (username, ip) {
    const challenge = {
      challenge: await randomString(32),
      date: moment().format(),
      ...this.extChallenge()
    };
    // legacy only getting the salt, optionally this
    // gets a limited user object for the challenge
    let salt = await this.db.getSalt(username);
    let extend = {};

    if (!salt) {
      return {
        Error: 'You either been IP banned or there is noch such user.',
        code: 403
      };
    }

    if (typeof salt === 'object') {
      extend = salt;
      salt = salt.salt;
      delete extend.salt;
    }

    if (
      (await this.db.setChallenge(username, challenge, ip, this.validTill)) !==
      'success'
    ) {
      // allow currently only a single auth request in parallel from the same ip
      return { auth: 'in progress', code: 409 };
    }

    return {
      code: 200,
      ...challenge,
      ...extend,
      hash: this.hash,
      salt,
      rounds: this.rounds
    };
  }

  async changePassword (username, ip, auth, newAuth) {
    const r = await this.auth(username, ip, auth);
    if (!r.auth) return r;

    const { hash, challenge, age } = await this.db.getAuth(username, ip);

    await this.db.setPassword(
      username,
      decrypt(
        newAuth,
        Buffer.from(hash.substr(0, 32), 'hex'),
        Buffer.from(hash.substr(32, 48), 'hex')
      )
    );

    return { code: 200, Error: false, success: true };
  }

  async auth (username, ip, auth) {
    const dbAuth = await this.db.getAuth(username, ip);
    const { hash, challenge, age } = dbAuth;
    let result;
    if (hash === null || challenge === null) {
      return {
        Error: 'Either the user or challenge does not exist',
        code: 403
      };
    }

    // either an age is provided or we take the date from the challenge
    if (
      (!this.providesAge &&
        moment(challenge.date).add(this.validTill).toDate() < new Date()) ||
      (this.providesAge && age > this.validTill)
    ) {
      this.db.cleanChallenge(username, ip, this.validTill);
      return { Error: 'Challenge expired', code: 409 };
    }

    if (typeof this.algorithm === 'function') {
      result = await this.algorithm(
        username,
        hash,
        challenge.challenge,
        this.options,
        auth
      );
    } else if (algos[this.algorithm]) {
      result = await algos[this.algorithm](challenge, this.domain, hash, this.rounds, auth, dbAuth);
    } else {
      result = await processRounds(challenge, this.domain, hash, this.rounds);
    }

    // Cleaning can happen async
    this.db.cleanChallenge(username, ip, 0);

    if (result === auth) {
      return { auth: true, Error: false, code: 200 };
    } else {
      return { auth: false, Error: false, code: 401 };
    }
  }
}

module.exports = SP;
