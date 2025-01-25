import jws from 'jws'
import axios from 'axios'

import {ACCESS_TOKEN_URL, EMBED_TOKEN_URL, EMBED_URL} from './constants.js' // Import necessary constants

/**
 * Fetches an embed token. If a valid token exists, it uses it; otherwise, it generates a new one.
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @param {Object} config - Configuration object with token details
 * @returns {Promise}
 */
function getEmbedToken(req, res, next, config) {
    return new Promise((resolve, reject) => {
        console.log('Getting embed token')
        // Check if an embed token exists and is not expired
        if (
            config.embedToken &&
            config.embedTokenExpiration &&
            config.embedTokenExpiration > secondsSinceEpoch()
        ) {
            resolve() // Use existing token
        } else {
            console.log('Embed token is expired')
            // Fetch a new access token before generating a new embed token
            getAccessToken(req, res, next, config).then(() => {
                console.log('Creating new embed token')
                axios
                    .post(
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
                    .then(function (response) {
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
                                console.log(
                                    `Embed token created: valid until ${config.embedTokenExpiration}`
                                )
                                resolve() // Successfully generated embed token
                            }
                        }
                    })
                    .catch(function (error) {
                        console.log('Error generating embed token:', error)
                        next(Error(error)) // Handle errors during the request
                    })
            })
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
        // Check if an access token exists and is not expired
        if (
            config.accessToken &&
            config.accessTokenExpiration > secondsSinceEpoch()
        ) {
            console.log(
                `Access token is valid for ${config.accessTokenExpiration - secondsSinceEpoch()} seconds`
            )
            resolve() // Use existing token
        } else {
            console.log('Access token is expired, creating a new one')
            axios
                .get(ACCESS_TOKEN_URL, {
                    headers: {
                        Authorization:
                            'Basic ' +
                            Buffer.from(config.clientId + ':' + config.clientSecret).toString(
                                'base64'
                            ), // Basic authentication header
                    },
                })
                .then(function (response) {
                    try {
                        const data = response.data
                        config.userId = data.userId // Save user ID
                        config.accessToken = data.access_token // Save new access token
                        // Set expiration to 60 seconds earlier
                        config.accessTokenExpiration =
                            Math.floor(Date.now() / 1000) + (data.expires_in - 60)
                        console.log(
                            'Access token created: valid until ' +
                            config.accessTokenExpiration
                        )
                        resolve() // Successfully generated access token
                    } catch (e) {
                        console.log('Error parsing access token response:', e)
                        next('Error parsing access token response') // Handle parsing errors
                    }
                })
                .catch(function (error) {
                    console.log('Error fetching access token:', error)
                    next(Error(error)) // Handle errors during the request
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
    console.log(`Query =`, query)
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
export {handleRequest, refreshEmbedToken, showFilters}
