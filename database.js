const  { MongoClient } = require('mongodb');

let databaseConnection;

module.exports = {
    connectToDatabase: (cb) => {
        MongoClient.connect('mongodb+srv://Vincent:kimVINH7991@cluster0.zr51e2p.mongodb.net/?retryWrites=true&w=majority')
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
