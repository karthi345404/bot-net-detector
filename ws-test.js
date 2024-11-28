const WebSocket = require('ws');
const ws = new WebSocket("ws://98.84.92.92:8080");

ws.onopen = () => {
    console.log("Connected to WebSocket server");
    ws.send("Hello from karthi");
};

ws.onmessage = (event) => {
    console.log("Received from server:", event.data);
};

ws.onclose = () => {
    console.log("Connection closed");
};

ws.onerror = (error) => {
    console.error("WebSocket error:", error);
};
