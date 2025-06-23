import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import type { User } from '@/lib/user'
import verifyToken from '@/lib/verifyToken'

interface VerifyTokenResponse {
  status: number
  message: string
  data?: { user: User }
}

export async function GET(req: NextRequest) {
  try {
    const token = req.cookies.get('token')?.value
    let response = (await verifyToken(token)) as VerifyTokenResponse
    if (
      !response ||
      response.status !== 200 ||
      !response.data ||
      !response.data.user
    ) {
      return NextResponse.json(
        { message: response?.message },
        { status: response?.status }
      )
    }
    const user: User = response.data.user
    // Exclude password from response
    const { password, ...userData } = user
    return NextResponse.json(userData)
  } catch (err: any) {
    return NextResponse.json(
      { message: 'Server error', error: err?.message },
      { status: 500 }
    )
  }
}
