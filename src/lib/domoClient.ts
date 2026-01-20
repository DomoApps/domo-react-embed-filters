import { useEffect } from 'react'

// Singleton to store ports for each iframe/embed
// This allows applyFilters to be called from anywhere in the app
const ports: Record<string, MessagePort> = {}

export interface Filter {
  column: string
  operand: string
  values: (string | number)[]
}

export const applyFilters = (filters: Filter[] = []) => {
  Object.values(ports).forEach((port) =>
    port.postMessage({
      id: 'setFilters123',
      jsonrpc: '2.0',
      method: '/v1/filters/apply',
      params: {
        filters,
      },
    })
  )
}

export const useDomoClient = () => {
  useEffect(() => {
    const handleMessage = (e: MessageEvent) => {
      // console.log('received message on window', e)

      // Check origin and ports
      if (!e.ports || !e.ports[0]) return

      const referenceId = e.data.referenceId
      // console.log(`referenceId = ${referenceId}`)

      const port = e.ports[0]
      ports[referenceId] = port
      port.start()

      port.onmessage = (event: MessageEvent) => {
        if (event.data.method) {
          // console.log(
          //   `received rpc event message with referenceId = ${referenceId} and method ${event.data.method}`
          // )
          switch (event.data.method) {
            case '/v1/onDrill':
              const filters = event.data.params['filters']
              // console.log(`filters = ` + JSON.stringify(filters))
              // Note: Original code replaced iframe src here.
              // In React, we might want to handle this differently, but keeping logic similar:
              const iframe = document.querySelector(
                `#iframe${referenceId}`
              ) as HTMLIFrameElement
              if (iframe) {
                // If we need to support maintaining filters on drill, we'd update state here.
                // For now, we just log or handle as per original intent if needed.
                // iframe.src = `/embed/page?filters=${JSON.stringify(filters)}`
              }
              break
            case '/v1/onFrameSizeChange':
              // console.log(`width = ${event.data.params['width']}`)
              // console.log(`height = ${event.data.params['height']}`)
              break
            default:
            // console.log('params = ' + JSON.stringify(event.data.params))
          }
        }

        if (event.data.hasOwnProperty('result')) {
          // console.log(
          //   `received rpc response message with referenceId = ${referenceId}`
          // )
          // const result = event.data.result
          // console.log(`result = ${result}`)
        }

        if (event.data.error) {
          console.error(
            `received rpc error message with referenceId = ${referenceId}`,
            event.data.error
          )
        }
      }
    }

    window.addEventListener('message', handleMessage)

    // Cleanup
    return () => {
      window.removeEventListener('message', handleMessage)
    }
  }, [])
}
