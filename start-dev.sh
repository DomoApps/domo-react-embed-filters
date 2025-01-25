#!/bin/bash
PORTS=(3000 3003)

for PORT in "${PORTS[@]}"; do
  PID=$(lsof -t -i:$PORT)
  if [ -z "$PID" ]; then
    echo "No process found on port $PORT"
  else
    kill -9 $PID
    echo "Process on port $PORT (PID: $PID) has been killed."
  fi
done
# Start the front-end
npm run dev &

# Start the back-end
#node ./back-end/server &
node ./back-end/server &

# Wait for all background jobs to finish
wait