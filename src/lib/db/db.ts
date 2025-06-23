import { JSONFilePreset } from 'lowdb/node'
import type { User } from '@/lib/user'

interface DBData {
  users: User[]
  embedTokens: Record<string, any>
}

const defaultData: DBData = {
  users: [],
  embedTokens: {},
}

const db = await JSONFilePreset<DBData>('users.json', defaultData)

export default db
