'use strict';

const Path = require('path');
const Hapi = require('hapi');
const SP = require('../');
const crypto = require('crypto');
const moment = require('moment');

let memory = {
  users: {
    test: {
      salt: 'test123123123123'
    }
  },
  challenges: {}
};

memory.users.test.hash = crypto
  .createHash('sha512')
  .update(`${memory.users.test.salt}password123`)
  .digest('hex');

const db = {
  getSalt: async function (username) {
    memory.users[username] = memory.users[username] || {};
    return memory.users[username].salt;
  },

  setChallenge: async function (username, challenge, ip, validTill) {
    if (!memory.challenges[username]) {
      memory.challenges[username] = {};
      memory.challenges[username][ip] = {};
    } else if (!memory.challenges[username][ip]) {
      memory.challenges[username][ip] = {};
    } else if (
      moment(memory.challenges[username][ip].date)
        .add(validTill)
        .toDate() > new Date()
    ) {
      return 'failed';
    }

    memory.challenges[username][ip] = challenge;
    return 'success';
  },

  getAuth: async function (username, ip) {
    return {
      challenge: memory.challenges[username][ip],
      hash: memory.users[username].hash
    };
  },

  cleanChallenge: async function (username, ip) {
    delete memory.challenges[username][ip];
    return true;
  }
};
const sp = new SP({
  db,
  domain: 'example.com'
});

const server = new Hapi.Server({
  routes: {
    files: {
      relativeTo: Path.join(__dirname, 'public')
    }
  },
  port: 5000
});

server
  .register(require('inert'))
  .then(() => {
    server.route({
      method: 'GET',
      path: '/',
      handler: {
        file: 'index.html'
      }
    });

    server.route({
      method: 'POST',
      path: '/challenge',
      handler: function (request) {
        const { username } = request.payload;
        const ip = request.info.remoteAddress;
        return sp.challenge(username, ip);
      }
    });

    server.route({
      method: 'POST',
      path: '/login',
      handler: function (request) {
        const { username, password } = request.payload;
        const ip = request.info.remoteAddress;
        return sp.auth(username, ip, password);
      }
    });
  })
  .then(() => server.start())
  .then(() => console.log('Server running at:', server.info.uri));
