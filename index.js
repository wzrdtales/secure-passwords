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
  }

  async challenge (username, ip) {
    const challenge = {
      challenge: await randomString(32),
      date: moment().format()
    };
    const salt = await this.db.getSalt(username);

    if (!salt) {
      return { Error: 'You either been IP banned or there is noch such user.' };
    }

    if (
      (await this.db.setChallenge(username, challenge, ip, this.validTill)) !==
      'success'
    ) {
      // allow currently only a single auth request in parallel from the same ip
      return { auth: 'in progress' };
    }

    return { ...challenge, hash: this.hash, salt: salt, rounds: this.rounds };
  }

  async auth (username, ip, auth) {
    const { hash, challenge } = await this.db.getAuth(username, ip);
    let result;
    if (hash === null || challenge === null) {
      return { Error: 'Either the user or challenge does not exist' };
    }

    if (
      moment(challenge)
        .add(this.validTill)
        .toDate() > new Date()
    ) {
      return { Error: 'Challenge expired' };
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
    this.db.cleanChallenge(username, ip);

    if (result === auth) {
      return { auth: true, Error: false };
    } else {
      return { auth: false, Error: false };
    }
  }
}

module.exports = SP;
