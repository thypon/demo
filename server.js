const dns = require('dns')

const asyncHandler = require('hapi-async-handler')
const authBearerToken = require('hapi-auth-bearer-token')
const hapi = require('hapi')
const Netmask = require('netmask').Netmask
const underscore = require('underscore')

const whitelist = require('./hapi-auth-whitelist')

const Server = async (options, runtime) => {
  const graylist = { addresses: process.env.IP_GRAYLIST && process.env.IP_GRAYLIST.split(',') }
  const server = new hapi.Server()

  server.connection({ port: process.env.PORT })

  if (!runtime) {
    runtime = options
    options = {}
  }
  underscore.defaults(options, { id: server.info.id, module: module, headersP: true, remoteP: true })
  if (!options.routes) options.routes = require('./controllers/index')

  if (graylist.addresses) {
    graylist.authorizedAddrs = []
    graylist.authorizedBlocks = []

    graylist.addresses.forEach((entry) => {
      if ((entry.indexOf('/') === -1) && (entry.split('.').length === 4)) return graylist.authorizedAddrs.push(entry)

      graylist.authorizedBlocks.push(new Netmask(entry))
    })
  }

  server.register(
    [ asyncHandler,
      authBearerToken,
      whitelist
    ], (err) => {
    if (err) {
      throw err
    }

    if (process.env.NODE_ENV === 'production') {
      server.register({ register: require('hapi-require-https'), options: { proxy: true } }, (err) => {
        console.log(err)
      })
    }

    if (runtime.login) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('github authentication was not enabled yet we are in production mode')
      }

      const bearerAccessTokenConfig = {
        allowQueryToken: true,
        allowMultipleHeaders: false,
        validateFunc: (token, callback) => {
          const tokenlist = process.env.TOKEN_LIST && process.env.TOKEN_LIST.split(',')
          callback(null, ((!tokenlist) || (tokenlist.indexOf(token) !== -1)), { token: token, scope: ['devops', 'ledger', 'QA'] }, null)
        }
      }

      server.auth.strategy('session', 'bearer-access-token', bearerAccessTokenConfig)
      server.auth.strategy('github', 'bearer-access-token', bearerAccessTokenConfig)
    }

    server.auth.strategy('simple', 'bearer-access-token', {
      allowQueryToken: true,
      allowMultipleHeaders: false,
      validateFunc: (token, callback) => {
        const tokenlist = process.env.TOKEN_LIST && process.env.TOKEN_LIST.split(',')
        callback(null, ((!tokenlist) || (tokenlist.indexOf(token) !== -1)), { token: token }, null)
      }
    })
  })

  server.ext('onPreResponse', (request, reply) => {
    const response = request.response

    if (response.isBoom && response.output.statusCode >= 500) {
      const error = response

      if (process.env.NODE_ENV === 'development') {
        error.output.payload.message = error.message
        if (error.body) {
          error.output.payload.body = error.body
        }
        error.output.payload.stack = error.stack

        return reply(error)
      }
    }

    if ((!response.isBoom) || (response.output.statusCode !== 401)) {
      if (typeof response.header === 'function') response.header('Cache-Control', 'private')
      return reply.continue()
    }

    return reply.continue()
  })

  server.route(await options.routes.routes(runtime, options))

  server.start((err) => {
    if (err) {
      throw err
    }

    let resolvers = underscore.uniq([ '8.8.8.8', '8.8.4.4' ].concat(dns.getServers()))

    dns.setServers(resolvers)

    // Hook to notify start script.
    if (process.send) { process.send('started') }
  })

  return server
}

module.exports = Server
