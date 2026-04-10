import { useEffect, useRef, useCallback } from "react";

export default function useWebSocket(onMessage) {
  const wsRef = useRef(null);
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    let reconnectTimer;

    function connect() {
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${proto}//${location.host}/ws`);
      wsRef.current = ws;

      ws.onopen = () => console.log("[WS] connected");

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          onMessageRef.current(msg);
        } catch {}
      };

      ws.onclose = () => {
        console.log("[WS] disconnected, reconnecting in 2s");
        reconnectTimer = setTimeout(connect, 2000);
      };

      ws.onerror = () => ws.close();
    }

    connect();

    // Keepalive ping every 30s
    const pingInterval = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send("ping");
      }
    }, 30000);

    return () => {
      clearTimeout(reconnectTimer);
      clearInterval(pingInterval);
      wsRef.current?.close();
    };
  }, []);
}
