import mongoose from "mongoose";

const connectToDatabase = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URL)
        console.log("****** DATABASE TO CONNECT HOGAYA MASLA FRONTEND MEIN HAI ******")
    } catch(error) {
        console.log(error)
    }
}

export default connectToDatabase