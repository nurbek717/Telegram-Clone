const nodemailer = require('nodemailer')
const bcrypt = require('bcrypt')
const otpModel = require('../models/otp.model')
const BaseError = require('../errors/base.error')

class MailService {
	constructor() {
		/**
		 * In local development you often won't have real SMTP credentials.
		 * If any of the SMTP_* envs are missing we skip creating a real
		 * transporter and only log OTP codes to the console.
		 */
		const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env

		if (SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS) {
			this.transporter = nodemailer.createTransport({
				host: SMTP_HOST,
				port: Number(SMTP_PORT),
				secure: false,
				auth: {
					user: SMTP_USER,
					pass: SMTP_PASS,
				},
			})
		} else {
			this.transporter = null
			console.warn(
				'SMTP configuration is missing. OTP codes will be logged to the console instead of being emailed.'
			)
		}
	}

	async sendOtp(to) {
		const otp = Math.floor(100000 + Math.random() * 900000) // 6 digit otp
		// Always log OTP in development so the user can see it
		console.log('Generated OTP for', to, ':', otp)

		const hashedOtp = await bcrypt.hash(otp.toString(), 10)
		await otpModel.create({ email: to, otp: hashedOtp, expireAt: new Date(Date.now() + 5 * 60 * 1000) })

		// If no SMTP transporter is configured, stop here – login flow still works using console OTP.
		if (!this.transporter) {
			return
		}

		try {
			await this.transporter.sendMail({
				from: process.env.SMTP_USER,
				to,
				subject: `OTP for verification ${new Date().toLocaleString()}`,
				html: `<h1>Your OTP is ${otp}</h1>`,
			})
		} catch (error) {
			// Do not break login entirely if email sending fails – just log the error.
			console.error('Error sending OTP email:', error.message || error)
		}
	}

	async verifyOtp(email, otp) {
		const otpData = await otpModel.find({ email })
		if (!otpData) throw BaseError.BadRequest('Otp not found')
		const currentOtp = otpData[otpData.length - 1]
		if (!currentOtp) throw BaseError.BadRequest('Otp not found')

		if (currentOtp.expireAt < new Date()) {
			throw BaseError.BadRequest('Your otp is expired')
		}

		const isValid = await bcrypt.compare(otp.toString(), currentOtp.otp)
		if (!isValid) throw BaseError.BadRequest('Invalid otp entered')

		await otpModel.deleteMany({ email })
		return true
	}
}

module.exports = new MailService()
