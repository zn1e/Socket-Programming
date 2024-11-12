# Socket Programming: DateTime UDP Protocol

 Two programs written in **Python** to simulate a DateTime client/server socket application. The *server* allows the other program, called *client*, to ask the server for the current date or time of day. The server offers to deliver this information in three different languages (English, Māori, German).

## Running the script:

1. Open two terminals on your machine.
2. Start the server on one of the terminals with the appropriate command line parameters: <br>`python3 server.py <port#1> <port#2> <port#3>`
3. Then start the client on the other terminal with the appropriate command line parameters: <br>
`python3 client.py <time/date> <localhost/IP address> <port#>`
    - For the server hostname / IP address parameter, you can use IP address *127.0.0.1* or hostname *localhost*.
    - For the port parameter, use the port number with which you started the server. <br>


> This was created as a requirement for **COSC264: Introduction to Computer Networks and Internet** course and received a grade of **96.62% (A+)**.
