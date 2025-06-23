import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import db from '../../../lib/db/db'
import jwt from 'jsonwebtoken'
import axios from 'axios'
import {
  EMBED_TOKEN_URL,
  ACCESS_TOKEN_URL,
  EMBED_URL
} from '../../../lib/constants.js'
import { Buffer } from 'buffer'

const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecretKey'

interface User {
  id: string
  username: string
  password: string
  lastLogin?: Date
  instance?: any
  embedID?: any
  dashboards?: any[]
  role?: string
  email?: string
  mappingValue?: string
}

export async function POST(req: NextRequest) {
  try {
    const { embedID } = await req.json()
    if (!embedID) {
      return NextResponse.json(
        { message: 'Embed ID is required' },
        { status: 400 }
      )
    }
    const token = req.cookies.get('token')?.value
    if (!token) {
      return NextResponse.json(
        { message: 'Not authenticated' },
        { status: 401 }
      )
    }
    let decoded: any
    try {
      decoded = jwt.verify(token, JWT_SECRET)
    } catch (err) {
      return NextResponse.json({ message: 'Invalid token' }, { status: 401 })
    }
    const users = db.data.users as User[]
    const user = users.find((u) => u.id === decoded.id)
    if (!user) {
      return NextResponse.json({ message: 'User not found' }, { status: 404 })
    }
    const dashboard = (user.dashboards || []).find(
      (dash: any) => dash.embedID === embedID
    )
    if (!dashboard) {
      return NextResponse.json(
        { message: 'Dashboard not found for the given embedID' },
        { status: 404 }
      )
    }
    const filters =
      dashboard.filter?.map((filter: any) => {
        const { column, operator, values } = filter
        // Values should already be arrays from normalizeFilters
        return { column, operator, values }
      }) || []

    // --- Begin getAccessToken logic ---
    let accessToken = null
    let accessTokenExpiration = 0
    try {
      const accessTokenResp = await axios.get(ACCESS_TOKEN_URL, {
        headers: {
          Authorization:
            'Basic ' +
            Buffer.from(
              process.env.DOMO_CLIENT_ID + ':' + process.env.DOMO_CLIENT_SECRET
            ).toString('base64')
        }
      })
      const data = accessTokenResp.data
      accessToken = data.access_token
      accessTokenExpiration =
        Math.floor(Date.now() / 1000) + (data.expires_in - 60)
    } catch (err: any) {
      return NextResponse.json(
        { message: 'Failed to fetch access token' },
        { status: 500 }
      )
    }

    // --- Begin getEmbedToken logic ---
    const embedTokenRequestBody = {
      sessionLength: 1440,
      authorizations: [
        {
          token: embedID,
          permissions: ['READ', 'FILTER', 'EXPORT'],
          filters: filters,
          policies: dashboard.policies || []
        }
      ]
    }
    const embedTokenEndpoint = EMBED_TOKEN_URL
    console.log('[EmbedToken] Fetching embed token from:', embedTokenEndpoint)
    console.log(
      '[EmbedToken] Request body:',
      JSON.stringify(embedTokenRequestBody, null, 2)
    )
    let domoResponse
    try {
      domoResponse = await axios.post(
        embedTokenEndpoint,
        embedTokenRequestBody,
        {
          headers: { Authorization: `Bearer ${accessToken}` }
        }
      )
      console.log('[EmbedToken] Response status:', domoResponse.status)
      console.log('[EmbedToken] Response headers:', domoResponse.headers)
      console.log(
        '[EmbedToken] Response body:',
        JSON.stringify(domoResponse.data, null, 2)
      )
    } catch (err: any) {
      if (err.response) {
        console.error(
          '[EmbedToken] Error response status:',
          err.response.status
        )
        console.error(
          '[EmbedToken] Error response headers:',
          err.response.headers
        )
        console.error(
          '[EmbedToken] Error response body:',
          JSON.stringify(err.response.data, null, 2)
        )
      } else {
        console.error('[EmbedToken] Error:', err)
      }
      return NextResponse.json(
        { message: 'Failed to fetch embed token', error: err?.message },
        { status: 500 }
      )
    }
    if (domoResponse.data.error) {
      return NextResponse.json(
        { message: domoResponse.data.error },
        { status: 500 }
      )
    }
    const embedToken = domoResponse.data.authentication

    // Return token and embed URL
    return NextResponse.json({
      embedToken,
      embedUrl: `${EMBED_URL}${embedID}`
    })
    // --- End getEmbedToken logic ---
  } catch (err: any) {
    return NextResponse.json(
      { message: 'Server error', error: err?.message },
      { status: 500 }
    )
  }
}
