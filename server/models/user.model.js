import mongoose, {Schema} from 'mongoose';

const UserSchema = mongoose.Schema(
    {
        firstName:{type: String, required: true},
        lastName:{type: String, required: true},
        username:{type: String, required: true, unique: true},
        email:{type: String, required: true, unique: true},
        password:{type: String, required: true},
        profileImage:{
            type: String, 
            required: false,
            default: "img_link"},
        isAdmin:{type: Boolean, default: false},
        roles:{
            type: [Schema.Types.ObjectId],
            require: true,
            ref: "Role"
        }
    },
    {
        timestamp: true
    }
);

export default mongoose.model("User", UserSchema);