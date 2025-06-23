// Shared User interface for the project
export interface User {
  id: string
  username: string
  password: string
  lastLogin?: Date
  instance?: any
  embedID?: any
  dashboards?: any[]
  role?: string
  email?: string
  mappingValue?: string | string[]
  domoRole?: string
  invitedBy?: string
  sidebarPinned?: boolean // User preference for sidebar pin state
}
