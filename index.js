'use strict';

const Promise = require('bluebird');
const crypto = require('crypto');
const moment = require('moment');

const processRounds = async (input, domain, prior, rounds) => {
  function hash (challenge, prior) {
    return crypto
      .createHash('sha512')
      .update(`${challenge.challenge}${challenge.date}${domain}${prior}`)
      .digest('hex');
  }

  // This should be optimized with process.nextTick
  // For now keep it simple but prepared
  return new Promise(resolve => {
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
    if (options.algorithm && !typeof options.algorithm === 'function') {
      throw new Error('Passed an invalid algorithm');
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
      date: moment().format()
    };
    const salt = await this.db.getSalt(username);

    if (!salt) {
      return {
        Error: 'You either been IP banned or there is noch such user.',
        code: 403
      };
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
      hash: this.hash,
      salt: salt,
      rounds: this.rounds
    };
  }

  async auth (username, ip, auth) {
    const { hash, challenge, age } = await this.db.getAuth(username, ip);
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
        moment(challenge.date)
          .add(this.validTill)
          .toDate() < new Date()) ||
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
        this.options
      );
    } else {
      result = await processRounds(challenge, this.domain, hash, this.rounds);
    }

    // Cleaning can happen async
    this.db.cleanChallenge(username, ip, this.validTill);

    if (result === auth) {
      return { auth: true, Error: false, code: 200 };
    } else {
      return { auth: false, Error: false, code: 401 };
    }
  }
}

module.exports = SP;
