import type { NextRequest } from 'next/server'
import { NextResponse } from 'next/server'
import db from '@/lib/db/db'
import bcrypt from 'bcryptjs'
import type { User } from '@/lib/user'
import verifyToken from '@/lib/verifyToken'

interface VerifyTokenResponse {
  status: number
  message: string
  data?: { user: User }
}

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

export async function PUT(req: NextRequest) {
  try {
    const users = db.data.users as User[]
    // Extract the id from the URL
    const url = new URL(req.url)
    const pathParts = url.pathname.split('/')
    const userId = pathParts[pathParts.length - 1]

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
    let user = response.data.user

    let targetUser = users.find((u) => u.id === userId)
    if (!targetUser) {
      return NextResponse.json({ message: 'User not found' }, { status: 404 })
    }
    // Allow updates to these fields only (no role logic)
    const updatableFields = [
      'username',
      'email',
      'mappingValue',
      'dashboards',
      'password',
      'sidebarPinned',
    ]
    const body = await req.json()
    // Process dashboards if present
    if (body.dashboards) {
      body.dashboards = body.dashboards.map((dashboard: any) => ({
        ...dashboard,
        filter: dashboard.filter ? normalizeFilters(dashboard.filter) : [],
      }))
    }
    // Update allowed fields
    for (const field of updatableFields) {
      if (field in body && field !== 'password') {
        ;(targetUser as any)[field] = body[field]
      }
    }
    // Handle password separately (hash if present)
    if ('password' in body && body.password) {
      targetUser.password = await bcrypt.hash(body.password, 10)
    }
    // Always allow domoRole to be updated
    if ('domoRole' in body) {
      targetUser.domoRole = body.domoRole
    }
    await db.write()

    // Process dashboards for the response
    const processedDashboards = (targetUser.dashboards || []).map(
      (dashboard: any) => ({
        name: dashboard.name,
        embedID: dashboard.embedID,
        filter: dashboard.filter || [],
      })
    )

    // Return both the updated user and processed dashboards
    return NextResponse.json({
      user: targetUser,
      dashboards: processedDashboards,
    })
  } catch (err: any) {
    return NextResponse.json({ message: err.message }, { status: 500 })
  }
}

export async function DELETE(req: NextRequest) {
  try {
    // Extract the id from the URL
    const url = new URL(req.url)
    const pathParts = url.pathname.split('/')
    const userId = pathParts[pathParts.length - 1]

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
    let user = response.data.user

    let targetUser = (db.data.users as User[]).find((u) => u.id === userId)
    if (!targetUser) {
      return NextResponse.json({ message: 'User not found' }, { status: 404 })
    }

    // Remove the user from the database (no role checks)
    db.data.users = ((db.data.users as User[]).filter((u) => u.id !== userId)) as User[]
    await db.write()

    return NextResponse.json({ message: 'User deleted successfully' })
  } catch (err: any) {
    return NextResponse.json({ message: err.message }, { status: 500 })
  }
}
