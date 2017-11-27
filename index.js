'use strict';

const Promise = require('bluebird');
const crypto = require('crypto');

const processRounds = async (input, domain, prior, rounds) => {
  let output = input;

  function hash (challenge, prior) {
    const hash = crypto.createHash('sha512');
    hash.update(`${challenge.challenge}${challenge.date}${domain}${prior}`);
    return hash.digest('hex');
  }

  // This should be optimized with process.nextTick
  // For now keep it simple but prepared
  return new Promise(resolve => {
    while (--rounds) {
      prior = hash(input, prior);
    }
    resolve(output);
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

    if (!options.db && typeof options.db !== 'object') {
      throw new Error('Missing database controller');
    }

    if (!options.domain && typeof options.domain !== 'string') {
      throw new Error('Missing TLD name.');
    }

    this.algorithm = options.algorithm;
    this.hash = options.hashAlgorithm;
    this.db = options.db;
    this.rounds = options.rounds || 10;
    // The default of 10 seconds should be reasonable enough
    this.validTill = options.validTill || 10 * 1000;
    this.options = options;
    this.domain = options.domain;
  }

  async challenge (username, ip) {
    const challenge = {
      challenge: randomString(32),
      date: new Date().toString()
    };
    const salt = await this.db.getSalt(username);

    if (
      (await this.db.setChallenge(username, challenge, ip, this.validTill)) !==
      'success'
    ) {
      // allow currently only a single auth request in parallel from the same ip
      return { auth: 'in progress' };
    }

    return { ...challenge, salt: salt };
  }

  async auth (username, ip, auth) {
    const { hash, challenge } = await this.db.getAuth(username, ip);
    let result;
    if (hash === null || challenge === null) {
      return { Error: 'Either the user or challenge does not exist' };
    }

    if (new Date(challenge) + this.validTill > new Date()) {
      return { Error: 'Challenge expired' };
    }

    if (typeof this.algorithm !== 'string') {
      result = await this.algorithm(
        username,
        hash,
        challenge.challenge,
        this.options
      );
    } else {
      result = processRounds(challenge, this.domain, hash, this.rounds);
    }

    // Cleaning can happen async
    this.db.cleanChallenge(username, ip);

    if (result === auth) {
      return { authenticated: 'true', Error: false };
    } else {
      return { authenticated: 'false', Error: false };
    }
  }
}

module.exports = SP;
