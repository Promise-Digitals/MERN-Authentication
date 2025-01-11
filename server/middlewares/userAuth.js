import jwt from 'jsonwebtoken'

const userAuth = async (req, res, next) => {
    const {token} = req.cookies;

    console.log(token)


    if (!token) {
        return res.json({
            success: false,
            message: "Not Autnorized, Login Again"
        }) 
    }

    try {

        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if (tokenDecode.id) {
            req.body.userId = tokenDecode.id
            
        }else{
            return res.json({
                success: false,
                message: "Not Autnorized, Login Again"
            }) 

        }

        next()
        
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        }) 
    }
}


export default userAuth;