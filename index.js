var kappa = require('kappa-core')
var events = require('events')
var inherits = require('inherits')
var level = require('level-mem')
var thunky = require('thunky')
var { box } = require('./lib/crypto')
var timestamp = require('monotonic-timestamp')
var sublevel = require('subleveldown')
var crypto = require('hypercore-crypto')
var createChannelView = require('./views/channels')
var createMembershipsView = require('./views/channel-membership')
var createMessagesView = require('./views/messages')
var createTopicsView = require('./views/topics')
var createUsersView = require('./views/users')
var createModerationView = require('./views/moderation')
var createArchivingView = require('./views/channel-archiving')
var createPrivateMessagesView = require('./views/private-messages')
var swarm = require('./swarm')

var DATABASE_VERSION = 1
var CHANNELS = 'c'
var MEMBERSHIPS = 'j' // j for joined memberships..? :3
var MESSAGES = 'm'
var TOPICS = 't'
var USERS = 'u'
var MODERATION_AUTH = 'mx'
var MODERATION_INFO = 'my'
var ARCHIVES = 'a' 
var PRIVATE_MESSAGES = 'p'

module.exports = Cabal
module.exports.databaseVersion = DATABASE_VERSION

/**
 * Create a new cabal. This is the object handling all
 * local nickname -> mesh interactions for a single user.
 * @constructor
 * @param {string|function} storage - A hyperdb compatible storage function, or a string representing the local data path.
 * @param {string|Buffer} key - a hypercore public key
 */
function Cabal (storage, key, opts) {
  if (!(this instanceof Cabal)) return new Cabal(storage, key, opts)
  if (!opts) opts = {}
  events.EventEmitter.call(this)
  this.setMaxListeners(Infinity)

  var json = {
    encode: function (obj) {
      return Buffer.from(JSON.stringify(obj))
    },
    decode: function (buf) {
      var str = buf.toString('utf8')
      try { var obj = JSON.parse(str) } catch (err) { return {} }
      return obj
    },
    buffer: true
  }

  this.maxFeeds = opts.maxFeeds
  this.modKeys = opts.modKeys || []
  this.adminKeys = opts.adminKeys || []
  this.preferredPort = opts.preferredPort || 13331

  if (!key) this.key = generateKeyHex()
  else {
    if (Buffer.isBuffer(key)) key = key.toString('hex')
    if (!key.startsWith('cabal://')) key = 'cabal://' + key
    this.key = sanitizeKey(key)
  }
  if (!isHypercoreKey(this.key)) throw new Error('invalid cabal key')

  this.db = opts.db || level()
  this.kcore = kappa(storage, {
    valueEncoding: json,
    encryptionKey: isHypercoreKey(this.key) ? this.key : null
  })

  // Create (if needed) and open local write feed
  var self = this
  this.feed = thunky(function (cb) {
    self.kcore.ready(function () {
      self.kcore.writer('local', function (err, feed) {
        cb(feed)
      })
    })
  })

  // views
  this.kcore.use('memberships', createMembershipsView(
    sublevel(this.db, MEMBERSHIPS, { valueEncoding: json })))
  this.kcore.use('channels', createChannelView(
    sublevel(this.db, CHANNELS, { valueEncoding: json })))
  this.kcore.use('messages', createMessagesView(
    sublevel(this.db, MESSAGES, { valueEncoding: json })))
  this.kcore.use('topics', createTopicsView(
    sublevel(this.db, TOPICS, { valueEncoding: json })))
  this.kcore.use('users', createUsersView(
    sublevel(this.db, USERS, { valueEncoding: json })))
  this.kcore.use('moderation', 2, createModerationView(
    this,
    sublevel(this.db, MODERATION_AUTH, { valueEncoding: json }),
    sublevel(this.db, MODERATION_INFO, { valueEncoding: json })
  ))
  this.kcore.use('archives', createArchivingView(
    this,
    sublevel(this.db, ARCHIVES, { valueEncoding: json })))
  this.feed((feed) => {
    self.kcore.use('privateMessages', createPrivateMessagesView(
       { public: feed.key, private: feed.secretKey },
      sublevel(self.db, PRIVATE_MESSAGES, { valueEncoding: json })))
    this.privateMessages = this.kcore.api.privateMessages
  })

  this.messages = this.kcore.api.messages
  this.channels = this.kcore.api.channels
  this.memberships = this.kcore.api.memberships
  this.topics = this.kcore.api.topics
  this.users = this.kcore.api.users
  this.moderation = this.kcore.api.moderation
  this.archives = this.kcore.api.archives
}

inherits(Cabal, events.EventEmitter)
Cabal.prototype.getDatabaseVersion = function (cb) {
  if (!cb) cb = noop
  process.nextTick(cb, DATABASE_VERSION)
}

/**
 * Get information about a user that they've volunteered about themselves.
 * @param {String} key - The hex key of the user.
 */
Cabal.prototype.getUser = function (key, cb) {
  if (typeof key === 'function') {
    cb = key
    key = null
  }

  var self = this

  this.feed(function (feed) {
    if (!key) key = feed.key.toString('hex')
    self.kcore.api.users.get(key, cb)
  })
}

/**
 * Publish a message to your feed.
 * @param {String} message - The message to publish.
 * @param {Object} opts - Options
 * @param {function} cb - When message has been successfully added.
 */
Cabal.prototype.publish = function (message, opts, cb) {
  if (!cb) cb = noop
  if (!message) return cb()
  if (typeof opts === 'function') return this.publish(message, null, opts)
  if (!opts) opts = {}

  this.feed(function (feed) {
    message.timestamp = message.timestamp || timestamp()
    feed.append(message, function (err) {
      cb(err, err ? null : message)
    })
  })
}

/**
 * Publish a message to your feed, encrypted to a specific recipient's key.
 * @param {String} text - The textual message to publish.
 * @param {String|Buffer[32]) recipientKey - A recipient's public key to encrypt the message to.
 * @param {function} cb - When the message has been successfully written.
 */
Cabal.prototype.publishPrivateMessage = function (text, recipientKey, cb) {
  if (!cb) cb = noop
  if (typeof text !== 'string') return process.nextTick(cb, new Error('text must be a string'))
  if (!isHypercoreKey(recipientKey)) return process.nextTick(cb, new Error('recipientKey must be a 32-byte hypercore key'))

  if (typeof recipientKey === 'string') recipientKey = Buffer.from(recipientKey, 'hex')

  this.feed(function (feed) {
    const message = {
      type: 'private/text',
      content: {
        recipients: [recipientKey.toString('hex')],
        text
      },
      timestamp: timestamp()
    }
// Note: we encrypt the message to the recipient, but also to ourselves (so that we can read our part of the convo!)
     const ciphertext = box(Buffer.from(JSON.stringify(message)), [recipientKey, feed.key]).toString('base64')
    const encryptedMessage = {
      type: 'encrypted',
      content: ciphertext
    }

    feed.append(encryptedMessage, function (err) {
      cb(err, err ? null : encryptedMessage)
    })
  })
}

Cabal.prototype.publishNick = function (nick, cb) {
  // TODO: sanity checks on reasonable names
  if (!cb) cb = noop
  if (!nick) return cb()

  this.feed(function (feed) {
    var msg = {
      type: 'about',
      content: {
        name: nick
      },
      timestamp: timestamp()
    }
    feed.append(msg, cb)
  })
}

Cabal.prototype.publishChannelTopic = function (channel, topic, cb) {
  if (!cb) cb = noop
  if (!channel || typeof channel !== 'string') return cb()
  if (!topic || typeof topic !== 'string') return cb()
  this.feed(function (feed) {
    var msg = {
      type: 'chat/topic',
      content: {
        channel: channel,
        text: topic
      },
      timestamp: timestamp()
    }
    feed.append(msg, cb)
  })
}

Cabal.prototype.getLocalKey = function (cb) {
  if (!cb) return

  this.feed(function (feed) {
    cb(null, feed.key.toString('hex'))
  })
}

Cabal.prototype.getMessage = function (feedAtSeq, cb) {
  if (typeof feedAtSeq === 'string') {
    var p = feedAtSeq.split('@')
    feedAtSeq = { key: p[0], seq: Number(p[1]) }
  }
  this.kcore._logs.feed(feedAtSeq.key).get(feedAtSeq.seq, cb)
}

Cabal.prototype.swarm = function (opts, cb) {
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }
  if (!cb) cb = noop
  const self = this

  swarm(this, opts, function (err, swarm) {
    if (err) return cb(err)
    self._swarm = swarm
    cb(null, swarm)
  })
}

Cabal.prototype.replicate = function (isInitiator, opts) {
  opts = opts || {}
  opts = Object.assign({}, {
    live: true,
    maxFeeds: 1024
  }, opts)
  return this.kcore.replicate(isInitiator, opts)
}

Cabal.prototype.ready = function (cb) {
  this.kcore.ready(cb)
}

Cabal.prototype._addConnection = function (key) {
  this.emit('peer-added', key)
}

Cabal.prototype._removeConnection = function (key) {
  this.emit('peer-dropped', key)
}

Cabal.prototype.close = function (cb) {
  const self = this

  if (this._swarm) {
    this._swarm.once('close', close)
    this._swarm.destroy()
  } else {
    close()
  }

  function close () {
    self.kcore.pause(function () {
      self.kcore._logs.close(cb)
    })
  }
}

function generateKeyHex () {
  return crypto.keyPair().publicKey.toString('hex')
}

function isHypercoreKey (key) {
  if (typeof key === 'string') return /^[0-9A-Fa-f]{64}$/.test(key)
  else if (Buffer.isBuffer(key)) return key.length === 32
}
module.exports.isHypercoreKey = isHypercoreKey

// Ensures 'key' is a hex string
function sanitizeKey (key) {
  const match = key.match(/^cabal:\/\/([0-9A-Fa-f]{64})/)
  if (match === null) return undefined
  return match[1]
}

function noop () {}
