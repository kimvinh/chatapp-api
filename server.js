const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const { ObjectId } = require('mongodb');
const { connectToDatabase, getDatabase } = require('./database');
const http = require('http');
const { Server } = require('socket.io');


// Init App & Middleware
const app = express();
const storageDirectory = path.join(__dirname, 'Storage');
// Serve files from the "server\Storage" directory
app.use('/files', express.static(storageDirectory));
app.use(express.json());
// Using 'bcrypt' to hash the password
const bcrypt = require('bcrypt');
const saltRounds = 10;
// Using session and cookie to store the status of logging
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const server = http.createServer(app);

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'Storage/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '_' + file.originalname);
    }
});

const upload = multer({ storage: storage })

app.use(cors({
    origin: ['https://chatapp-api-kkfv.onrender.com', 'https://chatapp-e5ar.onrender.com'],
    methods: ['GET', 'POST', 'DELETE', 'PUT', 'PATCH'],
    credentials: true
}));

const io = new Server(server, {
    cors: {
        origin: ['https://chatapp-api-kkfv.onrender.com:3001/', 'https://chatapp-e5ar.onrender.com'],
        methods: ['GET', 'POST', 'DELETE', 'PUT', 'PATCH']
    }
});

// Define a map to store the room info
const rooms = new Map();

// Define a map to store the users in each room
const roomUsers = new Map();

// Create a Map to store messages for each room
const messageList = new Map();

io.on("connection", (socket) => {
    // Handle the task when a user is creating a room
    socket.on("create_room", ({ roomID, roomPassword }) => {
        if (rooms.has(roomID)) {
            socket.emit("room_creation_failed", "Room ID already exists");
        } else {
            rooms.set(roomID, roomPassword);
            socket.emit("room_creation_success");
        }
    })

    // Handle the task when a user is joining the room
    socket.on("join_room", ({ roomID, roomPassword }) => {
        if (rooms.has(roomID) && rooms.get(roomID) === roomPassword) {
            socket.emit("join_success");
        } else {
            socket.emit('join_failed', 'Invalid room ID or password');
        }
    });

    socket.on("setup_room", ({ roomID, userID, fullName, isLogin, type, avatarURL, time }) => {
        socket.join(roomID);
        const authorInfo = {
            userSocketID: socket.id,
            authorID: userID,
            authorName: fullName,
            registered: isLogin,
            type: type,
            avatar: avatarURL
        }
        // Add the user to the room's users list
        if (roomUsers.has(roomID)) {
            const users = roomUsers.get(roomID);
            users.push(authorInfo);
            roomUsers.set(roomID, users);
        } else {
            roomUsers.set(roomID, [authorInfo]);
        }
    
        // Get the updated list of users in the room
        const usersInRoom = roomUsers.get(roomID);
    
        // Emit the "users_list" event to all users in the room with the updated list
        io.to(roomID).emit("users_list", usersInRoom);

        // Create a message package
        const messagePackage = {
            roomID: roomID,
            authorID: userID,
            authorName: fullName,
            message: `${fullName} has joined the room.`,
            type: 'user_join',
            time: time
        }

        // Send the message package to the client side
        io.to(roomID).emit('receive_message', messagePackage);
    })

    // Receive the message sent from the client
    socket.on("send_message", (messageData) => {
        const roomID = messageData.roomID;

        // Add the message to the room's messages list
        const messages = messageList.get(roomID) || [];
        messages.push(messageData);
        messageList.set(roomID, messages);

        // Broadcast the message to all users in the room
        io.to(roomID).emit("receive_message", messageData);
    });

    socket.on("join_private_room", (roomID) => {
        if (!rooms.has(roomID)) {
            rooms.set(roomID);
        }
        socket.join(roomID);
    })

    // Handle the task when the user leaves the room
    socket.on("leave_room", ({ roomID, userID, fullName, time }) => {
        socket.leave(roomID);

        // Remove the user from the room's users list
        if (roomUsers.has(roomID)) {
            let users = roomUsers.get(roomID);
            let userIndex = users.findIndex((user) => user.authorID === userID);
            users = users.filter((e, index) => index !== userIndex);
            if (users.length) {
                let messagePackage = {
                    roomID: roomID,
                    author: fullName,
                    message: `${fullName} left the room.`,
                    type: 'user_leave',
                    time: time
                }
        
                io.to(roomID).emit('receive_message', messagePackage);

                roomUsers.set(roomID, users);

                const hostIndex = users.findIndex((user) => user.type === 'host');
                if (hostIndex === -1) {
                    userIndex = Math.floor(Math.random() * users.length);
                    users[userIndex].type = 'host';

                    delete messagePackage.author;
                    delete messagePackage.time;
                    messagePackage = {
                        roomID: roomID,
                        message: `${users[userIndex].authorName} becomes the host of the room.`,
                        type: 'notification'
                    }
                    io.to(roomID).emit('receive_message', messagePackage);
                }

                // Emit the "users_list" event to all users in the room with the updated list
                io.to(roomID).emit("users_list", roomUsers.get(roomID));
            } else {
                rooms.delete(roomID);
                roomUsers.delete(roomID);
            }
        }
    });

    socket.on("transfer_host", ({ roomID, currentHostID, newHostID}) => {
        if (rooms.has(roomID)) {
            const users = roomUsers.get(roomID);

            // Find the current host and update their type to 'regular'
            const currentHostIndex = users.findIndex((user) => user.authorID === currentHostID);
            users[currentHostIndex].type = 'regular';

            // Find the new host and update their type to 'host'
            const newHostIndex = users.findIndex((user) => user.authorID === newHostID);
            users[newHostIndex].type = 'host';

            const messagePackage = {
                roomID: roomID,
                message: `${users[newHostIndex].authorName} becomes the host of the room.`,
                type: 'notification'
            }
            io.to(roomID).emit('receive_message', messagePackage);

            // Emit the "users_list" event to all users in the room with the updated list
            io.to(roomID).emit("users_list", roomUsers.get(roomID));
        }
    });

    socket.on("kick_user", ({ roomID, kickedUserID }) => {
        if (rooms.has(roomID)) {
            let users = roomUsers.get(roomID);
            const targetedIndex = users.findIndex((user) => user.authorID === kickedUserID);
            const targetedUser = users[targetedIndex].authorName;
            users = users.filter((e, index) => index !== targetedIndex);
            roomUsers.set(roomID, users);

            const messagePackage = {
                roomID: roomID,
                message: `${targetedUser} was kicked out of the room.`,
                type: 'notification'
            }
            io.to(roomID).emit('receive_message', messagePackage);

            // Emit the "users_list" event to all users in the room with the updated list
            io.to(roomID).emit("users_list", roomUsers.get(roomID));
        }
    })

    socket.on("send_friend_request", ({ roomID, friendRequest }) => {
        if (rooms.has(roomID)) {
            const users = roomUsers.get(roomID);
            
            const requestedFromUser = users.find((user) => user.authorID === friendRequest.requestedFrom);
            delete requestedFromUser.registered;
            delete requestedFromUser.type;
            
            const beingRequestedUser = users.find((user) => user.authorID === friendRequest.beingRequested);
            delete beingRequestedUser.registered;
            delete beingRequestedUser.type;
            
            friendRequest = {
                requestedFrom: requestedFromUser,
                beingRequested: beingRequestedUser
            }

            io.to(beingRequestedUser.userSocketID).emit("receive_friend_request", friendRequest);
        }
    })

    socket.on("send_friend_request_response", (response) => {
        const { roomID, isAccepted, friendRequest } = response;
        if (rooms.has(roomID)) {
            io.to(friendRequest.requestedFrom.userSocketID).emit("receive_friend_request_response", { isAccepted, friendRequest, youAre: 'requesting' })
            io.to(friendRequest.beingRequested.userSocketID).emit("receive_friend_request_response", { isAccepted, friendRequest, youAre: 'requested' })
        }
    })
});

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    key: "token",
    secret: "testing",
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: getRemainingTimeUntilEndOfDay(),
    }
}))

// Helper function to calculate the remaining time until the end of the day
function getRemainingTimeUntilEndOfDay() {
    const now = new Date();
    const endOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1, 0, 0, 0, 0);
    const remainingTime = endOfDay - now;
    return remainingTime;
}

// Database Connection
let db;

connectToDatabase((err) => {
    if (!err) {
        
        db = getDatabase();
        db.collection('users').createIndex({ username: 1 }, { unique: true });
        db.collection('users').createIndex({ email: 1 }, { unique: true });

        server.listen(3001, () => {
            console.log('Database is connecting ...')
            console.log('App listening on port 3001.');
        });
    }
});

// Routes
app.get('/', (req, res) => {
    if (req.session.user) {
        db.collection('users')
            .findOne({ _id: new ObjectId(req.session.user._id) })
            .then((result) => {
                req.session.user = result;
                res.send({
                    loggedIn: true,
                    user: result
                });
            });
    } else {
        res.send({ loggedIn: false })
    }
})

app.get('/users', (req, res) => {
    let users = [];
    db.collection('users')
        .find()
        .forEach(user => users.push(user))
        .then(() => {
            res.status(200).json(users);
        })
        .catch(() => {
            res.status(500).json({ error: 'Could not fetch the document' })
        })
});

app.post('/users/login', (req, res) => {
    const { username, password } = req.body;

    db.collection('users')
        .findOne({ username: username })
        .then((document) => {
            if (document) {
                bcrypt.compare(password, document.password, (err, response) => {
                    if (response) {
                        req.session.user = document;
                        res.status(200).json({ message: 'Login Successfully' })
                    } else {
                        res.status(401).json({ message: 'Incorrect Password'})
                    }
                })
            } else {
                res.status(401).json({ message: 'Incorrect Username' })
            }
        })
        .catch(err => {
            res.status(500).json({ error: 'Could not fetch the document' })
        });
});

// Helper function to hash the password using bcrypt
async function hashPassword(password) {
    try {
        const hash = await bcrypt.hash(password, saltRounds);
        return hash;
    } catch (error) {
        console.error('Error hashing password:', error);
        throw error;
    }
};

app.post('/users/register', async (req, res) => {
    let user = req.body;

    try {
        const hashedPassword = await hashPassword(user.password);
        user.password = hashedPassword;
        db.collection('users')
        .insertOne(user)
        .then((result) => {
            res.status(200).json(result)
        })
        .catch(err => {
            if (err.code === 11000) {
                res.status(400).json({ error: 'Username or email already exists' });
            } else {
                res.status(500).json({ error: 'Could not create a new document' });
            }
        });
    } catch (error) {
        res.send({ error: 'An error occurred during sign up' });
    }
});

app.post('/users/check-availability', (req, res) => {
    const checkValue = req.body;
    db.collection('users')
        .countDocuments(checkValue)
        .then((result) => {
            res.status(200).json(result);
        })
        .catch(err => {
            res.status(500).json({ err: 'Something is wrong' })
        })
});

app.delete('/users/:id', (req, res) => {
    if (ObjectId.isValid(req.params.id)) {
        db.collection('users')
            .deleteOne({ _id: new ObjectId(req.params.id) })
            .then((result) => {
                res.status(200).json(result)
            })
            .catch(err => {
                res.status(500).json({ error: 'Could not delete the document' })
            })
    } else {
        res.status(500).json({ error: 'Not valid doc id' })
    }
});

app.patch('/users/update/:id', (req, res) => {
    const updates = req.body.userInfo;
    delete updates._id;
    if (ObjectId.isValid(req.params.id)) {
        db.collection('users')
            .updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates })
            .then((result) => {
                res.status(200).json(result);
            })
            .catch(err => {
                res.status(500).json({ error: 'Could not delete the document' })
            })
    } else {
        res.status(500).json({ error: 'Not valid doc id' })
    }
});

app.post('/logout', (req, res) => {
    // Logout Logic
    req.session.destroy((err) => {
        if (err) {
            res.send({ message: 'Error occurred while logging out' });
        } else {
            res.clearCookie('token'); // Clear the session cookie
            res.send({ message: 'Logged out successfully' });
        }
    })
});

app.post('/file/upload', upload.single('file'), (req, res) => {
    const filePath = `/${req.file.filename}`;
    res.json({ filePath });
});

app.get('/file/download/:filename', (req, res) => {
    const filePath = path.join(storageDirectory, req.params.filename);
    const originalFileName = req.params.filename.split('_')[1];
    res.download(filePath, originalFileName);
})

app.post('/addfriend', (req, res) => {
    const { userID, friendInfo } = req.body;
    db.collection('users')
        .updateOne({ _id: new ObjectId(userID) }, { $push: { friends: friendInfo }})
    res.json({ message: "Sent" })
})

app.patch('/unfriend', async (req, res) => {
    const { user, target } = req.body;
    const targetUser = await db.collection('users').findOne({ _id: new ObjectId(target.authorID) });
    const updatedTargetFriends = targetUser.friends.filter((friend) => friend.authorID !== user._id);
    await db.collection('users')
        .updateOne(
            { _id: new ObjectId(target.authorID) }, 
            { $set: { friends: updatedTargetFriends } }
        )

    const updatedUserFriends = user.friends.filter((friend) => friend.authorID !== target.authorID);
    await db.collection('users')
        .updateOne(
            { _id: new ObjectId(user._id) }, 
            { $set: { friends: updatedUserFriends }}
        )

    user.friends = updatedUserFriends;
    res.status(200).json({ user: user })
})

app.get('/conversation', (req, res) => {
    const { user_1_id, user_2_id } = req.query;
    db.collection('conversations').findOne({
        participants: { $all: [user_1_id, user_2_id] }
    })
    .then((result) => {
        if (result) {
            res.status(200).json({ message: 'Found', conversation: result })
        } else {
            res.status(200).json({ message: 'Not Found' })
        }
    })
})

app.post('/conversation', (req, res) => {
    const conversation = req.body;
    db.collection('conversations')
        .insertOne(conversation)
        .then((result) => {
            res.status(200).json(result);
        });
})

app.get('/conversations', async (req, res) => {
    if (req.session.user) {
        const userID = req.session.user._id;
        const result = await db.collection('conversations').find({ 'participantsInfo.userID' : userID }).toArray();
        res.status(200).json(result);
    }
})

app.patch('/update_conversation', (req, res) => {
    db.collection('conversations')
        .updateOne({ _id: new ObjectId(req.body.conversationID) }, { $push: { messages: req.body.messageData } })
        .then((result) => {
            res.status(200).json(result);
        })
})

app.get('/get_messages', (req, res) => {
    const { conversationID } = req.query;
    db.collection('conversations')
        .findOne({ _id: new ObjectId(conversationID) })
        .then((result) => {
            res.status(200).json(result.messages);
        })
})