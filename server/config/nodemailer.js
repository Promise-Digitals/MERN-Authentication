import nodemailer from 'nodemailer'

// Using brevo smtp server
// const transporter = nodemailer.createTransport({
//     host: "smtp-relay.brevo.com",
//     port: 587,
//     auth: {
//         user: process.env.SMTP_USER,
//         pass: process.env.SMTP_PASS
//     }
// })


const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    auth: {
        user: process.env.SENDER_EMAIL,
        pass: "qawjobhoebdbwvee"
    }
})


export default transporter;