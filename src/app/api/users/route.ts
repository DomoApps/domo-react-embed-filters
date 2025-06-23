import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import db from '@/lib/db/db'
import bcrypt from 'bcryptjs'
import { v4 as uuidv4 } from 'uuid'
import type { User } from '@/lib/user'
import verifyToken from '@/lib/verifyToken'

interface VerifyTokenResponse {
  status: number
  message: string
  data?: { user: User }
}

import processDashboardFilters from '@/lib/processDashboardFilters'

// Utility to normalize filters for dashboards
const ARRAY_OPERATORS = ['IN', 'NOT_IN', 'EQUALS', 'NOT_EQUALS'] as const
type FilterOperator = (typeof ARRAY_OPERATORS)[number]

function normalizeFilters(filters: any[]) {
  console.log(
    '[normalizeFilters] Input filters:',
    JSON.stringify(filters, null, 2)
  )
  const normalized = filters.map((filter) => {
    // Convert values to array for supported operators
    if (ARRAY_OPERATORS.includes(filter.operator)) {
      if (Array.isArray(filter.values)) {
        return filter
      }
      return {
        ...filter,
        values:
          typeof filter.values === 'string'
            ? filter.values.split(',').map((v: string) => v.trim())
            : [filter.values],
      }
    }
    return filter
  })
  console.log(
    '[normalizeFilters] Output filters:',
    JSON.stringify(normalized, null, 2)
  )
  return normalized
}

export async function GET(req: NextRequest) {
  try {
    let token = req.cookies.get('token')?.value
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
    let user = response.data.user
    // Always return all users, with password removed
    const users = db.data.users as User[]
    const usersWithoutPassword = users.map(({ password, ...rest }) => rest)
    return NextResponse.json(usersWithoutPassword)
  } catch (err: any) {
    return NextResponse.json({ message: err.message }, { status: 500 })
  }
}

export async function POST(req: NextRequest) {
  try {
    const users = db.data.users as User[]
    const { username, email, mappingValue, password, dashboards, domoRole } =
      await req.json()

    // Check for duplicate username or email (case-insensitive)
    const duplicateUser = users.find(
      (u) =>
        (u.username &&
          username &&
          u.username.toLowerCase() === username.toLowerCase()) ||
        (u.email && email && u.email.toLowerCase() === email.toLowerCase())
    )
    if (duplicateUser) {
      return NextResponse.json(
        { message: 'A user with that username or email already exists.' },
        { status: 409 }
      )
    }

    // Enforce password is required
    if (!password || typeof password !== 'string' || password.trim() === '') {
      return NextResponse.json(
        { message: 'Password is required for user creation.' },
        { status: 400 }
      )
    }
    processDashboardFilters(dashboards)
    const hashedPassword = await bcrypt.hash(password, 10)
    let token = req.cookies.get('token')?.value
    let response = (await verifyToken(token)) as VerifyTokenResponse
    let creator = response && response.data ? response.data.user : null
    const normalizedDashboards = (dashboards || []).map((dashboard: any) => ({
      ...dashboard,
      filter: dashboard.filter ? normalizeFilters(dashboard.filter) : [],
    }))
    const newUser: User = {
      id: uuidv4(),
      username,
      email,
      mappingValue,
      dashboards: normalizedDashboards,
      password: hashedPassword,
      invitedBy: creator ? creator.id : undefined,
      domoRole: domoRole || '',
      sidebarPinned: true, // Set default to pinned
    }
    ;(db.data.users as User[]).push(newUser)
    await db.write()
    return NextResponse.json(newUser, { status: 201 })
  } catch (err: any) {
    return NextResponse.json(
      { message: 'Error adding user', error: err?.message },
      { status: 500 }
    )
  }
}
