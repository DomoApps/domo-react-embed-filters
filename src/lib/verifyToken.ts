import jwt from 'jsonwebtoken'
import db from '@/lib/db/db'
import type { User } from '@/lib/user'

const JWT_SECRET = process.env.JWT_SECRET || 'defaultSecretKey'

export interface VerifyTokenResponse {
  status: number
  message: string
  data?: { user: User }
}

/**
 * Function to verify the JWT token from the request cookies
 * @param token - The JWT token string
 * @returns Response object with status and message or user data
 */
const verifyToken = async (token: string | undefined): Promise<VerifyTokenResponse> => {
  if (!token) {
    return {
      status: 401,
      message: 'Invalid Token',
    }
  }
  let decoded: any
  try {
    decoded = jwt.verify(token, JWT_SECRET)
  } catch (err) {
    return {
      status: 401,
      message: 'Invalid or expired token',
    }
  }
  const users = db.data.users as User[]
  const user = users.find((user) => user.id === decoded.id)
  if (!user) {
    return {
      status: 404,
      message: 'User Not found',
    }
  }
  return {
    status: 200,
    message: 'Success',
    data: { user },
  }
}

export default verifyToken
