import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import db from '@/lib/db/db'
import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid'
import type { User } from '@/lib/user'

export async function POST(req: NextRequest) {
  try {
    const { embedID } = await req.json()
    const token = req.cookies.get('token')?.value

    if (!token) {
      return NextResponse.json(
        { message: 'Unauthorized: Please log in' },
        { status: 401 }
      )
    }
    if (!embedID) {
      return NextResponse.json(
        { message: 'Missing embedID in the request' },
        { status: 400 }
      )
    }

    const decoded: any = jwt.verify(
      token,
      process.env.JWT_SECRET || 'defaultSecretKey'
    )
    const users = db.data.users as User[]
    const user = users.find((user: User) => user.id === decoded.id)

    if (!user) {
      return NextResponse.json({ message: 'User not found' }, { status: 404 })
    }

    // Check if mappingValue contains a comma and convert to list if needed
    let mappingValue = user.mappingValue
    if (typeof mappingValue === 'string' && mappingValue.includes(',')) {
      mappingValue = mappingValue.split(',').map((item: string) => item.trim())
    }

    // Create the JWT body for the edit request
    const jwtBody: any = {
      sub: user.username,
      name: user.username,
      role: user.domoRole || 'Participant',
      email: user.email,
      jti: uuidv4(), // Unique identifier for the token
    }
    jwtBody[process.env.KEY_ATTRIBUTE!] = mappingValue

    // Generate an edit token with a 5-minute expiration
    const edit_token = jwt.sign(
      jwtBody,
      process.env.JWT_SECRET || 'defaultSecretKey',
      {
        expiresIn: '5m',
      }
    )

    // Construct the edit URL with the token
    const editUrl = `${process.env.IDP_URL}/jwt?token=${edit_token}`

    return NextResponse.json(editUrl)
  } catch (error) {
    console.error('Error in /api/editEmbed:', error)
    return NextResponse.json(
      { message: 'Server error occurred' },
      { status: 500 }
    )
  }
}
