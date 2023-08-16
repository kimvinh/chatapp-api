const  { MongoClient } = require('mongodb');

let databaseConnection;

module.exports = {
    connectToDatabase: (cb) => {
        MongoClient.connect('mongodb://localhost:27017/chat_app')
            .then((client) => {
                databaseConnection = client.db()
                return cb()
            })
            .catch(err => {
                console.log(err);
                return cb(err)
            })
    },
    getDatabase: () => databaseConnection
}