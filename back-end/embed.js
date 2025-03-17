import jws from 'jws'
import axios from 'axios'
import db from './db/db.js'
import { ACCESS_TOKEN_URL, EMBED_TOKEN_URL, EMBED_URL } from './constants.js' // Import necessary constants

// Token cache at module level
let tokenCache = {
  accessToken: null,
  accessTokenExpiration: 0,
  clientId: null,
  clientSecret: null,
}

/**
 * Get embed token from database
 * @param {string} userId - The user ID
 * @param {string} dashboardId - The dashboard ID
 * @returns {Object|null} The cached token data or null if not found/expired
 */
async function getEmbedTokenFromDB(userId, dashboardId) {
  // Ensure embedTokens exists
  if (!db.data.embedTokens) {
    db.data.embedTokens = {}
    await db.write()
  }

  const tokenKey = `${userId}_${dashboardId}`

  const tokenData = db.data.embedTokens[tokenKey]

  if (!tokenData) {
    return null
  }

  // Check if token is expired
  if (tokenData.expiration <= Math.floor(Date.now() / 1000)) {
    console.log('Token found but expired, removing from cache')
    console.log('Token expiration:', tokenData.expiration)
    console.log('Current time:', Math.floor(Date.now() / 1000))
    // Remove expired token
    delete db.data.embedTokens[tokenKey]
    await db.write()
    return null
  }

  return tokenData
}

/**
 * Save embed token to database
 * @param {string} userId - The user ID
 * @param {string} dashboardId - The dashboard ID
 * @param {Object} tokenData - The token data to cache
 */
async function saveEmbedTokenToDB(userId, dashboardId, tokenData) {
  // Ensure embedTokens exists
  if (!db.data.embedTokens) {
    db.data.embedTokens = {}
  }

  const tokenKey = `${userId}_${dashboardId}`

  db.data.embedTokens[tokenKey] = {
    token: tokenData.token,
    expiration: tokenData.expiration,
    filters: tokenData.filters,
  }

  // Write changes to the JSON file
  await db.write()
}

/**
 * Fetches an embed token. If a valid token exists, it uses it; otherwise, it generates a new one.
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @param {Object} config - Configuration object with token details
 * @returns {Promise}
 */
function getEmbedToken(req, res, next, config) {
  return new Promise(async (resolve, reject) => {
    console.log('Getting embed token')
    console.log('Config embedId:', config.embedId)

    // Get user ID from the request
    const userId = req.user?.id
    if (!userId) {
      console.log('No user ID found in request')
      next(Error('User ID not found in request'))
      return
    }

    try {
      // Try to get cached token from database
      const cachedToken = await getEmbedTokenFromDB(userId, config.embedId)

      if (cachedToken) {
        // Check if filters match
        if (
          JSON.stringify(cachedToken.filters) === JSON.stringify(config.filters)
        ) {
          console.log('Using cached embed token from database')
          config.embedToken = cachedToken.token
          config.embedTokenExpiration = cachedToken.expiration
          resolve()
          return
        } else {
          console.log('Cached token found but filters do not match')
        }
      }

      console.log('Embed token is expired or not cached')
      // Fetch a new access token before generating a new embed token
      getAccessToken(req, res, next, config).then(async () => {
        console.log('Creating new embed token')
        try {
          const response = await axios.post(
            EMBED_TOKEN_URL,
            {
              sessionLength: 1440, // Session length in minutes (24 hours)
              authorizations: [
                {
                  token: config.embedId, // Embed ID for the authorization
                  permissions: ['READ', 'FILTER', 'EXPORT'], // Allowed actions
                  filters: config.filters, // Additional filters
                  policies: config.policies, // Custom policies
                },
              ],
            },
            {
              headers: {
                Authorization: 'Bearer ' + config.accessToken, // Use access token for authorization
                'content-type': 'application/json; charset=utf-8',
                accept: '*/*',
              },
            }
          )

          // Check for errors in the response
          if (response.data.error) {
            console.log(response.data)
            next(Error(response.data.error)) // Pass error to next middleware
          } else {
            // Save the new embed token
            config.embedToken = response.data.authentication
            const decodedToken = jws.decode(config.embedToken)

            // Ensure the embed token contains the required "emb" field
            if (decodedToken.payload.emb.length === 0) {
              next(
                Error(
                  'The emb field in the embed token is empty. This usually means the user associated with the clientid/clientsecret does not have access to this card.'
                )
              )
            } else {
              // Set token expiration to 60 seconds earlier to avoid invalid tokens
              config.embedTokenExpiration = decodedToken.payload.exp - 60

              // Save to database
              await saveEmbedTokenToDB(userId, config.embedId, {
                token: config.embedToken,
                expiration: config.embedTokenExpiration,
                filters: config.filters,
              })

              console.log(
                `Embed token created: valid until ${config.embedTokenExpiration}`
              )
              resolve() // Successfully generated embed token
            }
          }
        } catch (error) {
          console.log('Error generating embed token:', error)
          next(Error(error)) // Handle errors during the request
        }
      })
    } catch (error) {
      console.error('Error in getEmbedToken:', error)
      next(Error(error))
    }
  })
}

/**
 * Fetches an access token. If a valid token exists, it uses it; otherwise, it generates a new one.
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @param {Object} config - Configuration object with token details
 * @returns {Promise}
 */
function getAccessToken(req, res, next, config) {
  return new Promise((resolve, reject) => {
    console.log('Getting access token')
    // Update cache with current client credentials if they've changed
    if (
      tokenCache.clientId !== config.clientId ||
      tokenCache.clientSecret !== config.clientSecret
    ) {
      tokenCache = {
        accessToken: null,
        accessTokenExpiration: 0,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
      }
    }

    // Check if a valid token exists in the cache
    if (
      tokenCache.accessToken &&
      tokenCache.accessTokenExpiration > secondsSinceEpoch()
    ) {
      console.log(
        `Using cached access token valid for ${
          tokenCache.accessTokenExpiration - secondsSinceEpoch()
        } seconds`
      )
      config.accessToken = tokenCache.accessToken
      config.accessTokenExpiration = tokenCache.accessTokenExpiration
      resolve()
    } else {
      console.log('Access token is expired, creating a new one')
      axios
        .get(ACCESS_TOKEN_URL, {
          headers: {
            Authorization:
              'Basic ' +
              Buffer.from(config.clientId + ':' + config.clientSecret).toString(
                'base64'
              ),
          },
        })
        .then(function (response) {
          try {
            const data = response.data
            config.userId = data.userId
            config.accessToken = data.access_token
            config.accessTokenExpiration =
              Math.floor(Date.now() / 1000) + (data.expires_in - 60)

            // Update the cache
            tokenCache.accessToken = config.accessToken
            tokenCache.accessTokenExpiration = config.accessTokenExpiration

            console.log(
              'Access token created: valid until ' +
                config.accessTokenExpiration
            )
            resolve()
          } catch (e) {
            console.log('Error parsing access token response:', e)
            next('Error parsing access token response')
          }
        })
        .catch(function (error) {
          console.log('Error fetching access token:', error)
          next(Error(error))
        })
    }
  })
}

/**
 * Returns the current time in seconds since the epoch (Unix timestamp).
 * @returns {number} Seconds since epoch
 */
function secondsSinceEpoch() {
  return Math.floor(Date.now() / 1000)
}

/**
 * Sends embed token and URL as the response.
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Object} config - Configuration object with token details
 */
function returnEmbedInfo(req, res, config) {
  console.log('Returning embed info')
  res.json({
    embedToken: config.embedToken,
    embedUrl: `${EMBED_URL}${config.embedId}${
      process.env.USE_XHR ? '' : `?referenceId=${req.params.itemId}`
    }`,
  })
}

/**
 * Handles the request to fetch an embed token and returns embed information.
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @param {Object} config - Configuration object with token details
 */
function handleRequest(req, res, next, config) {
  getEmbedToken(req, res, next, config).then(() => {
    returnEmbedInfo(req, res, config) // Return embed info after token retrieval
  })
}

/**
 * Displays filters in a simple HTML response for debugging or visualization.
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
function showFilters(req, res) {
  const query = req.query
  res.send(`
  <html>
    <body>
      <div style="margin: 20px; font-size: 24px; line-height: 30px;">
        Transitioning content based on mouse click for the following filter:
        <pre style="line-height: 20px; font-size: 16px; color: lightslategrey;">
          ${JSON.stringify(query.filters, null, 4)}
        </pre>
      </div>
    </body>
  </html>
  `)
}

/**
 * Refreshes the embed token by calling `getEmbedToken`.
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @param {Object} config - Configuration object with token details
 * @returns {Promise}
 */
function refreshEmbedToken(req, res, next, config) {
  return getEmbedToken(req, res, next, config)
}

// Export functions for use in other parts of the application
export { handleRequest, refreshEmbedToken, showFilters }
