const { X509Certificate } = require('crypto')
const fs = require('fs')
const asn1 = require('asn1js')
const pkijs = require('pkijs')
const pvutils = require('pvutils')

const x509 = require('@peculiar/x509')

const getBasicConstraintPathLength = (cert) => {
	const c = new x509.X509Certificate(cert.toJSON())
	return c.extensions.find((e) => e.type === '2.5.29.19')?.pathLength
}

const getRootCertificates = () => {
	return readCertificateChain('./trust_store.pem')
}

const getRevocationListSerialNumbers = (path) => {
	const crlData = fs.readFileSync(path, (err, crlData) => {
		if (err) {
			throw err
		}
	})

	const buffer = new Uint8Array(crlData).buffer
	const asn1crl = asn1.fromBER(buffer)
	const crl = new pkijs.CertificateRevocationList({
		schema: asn1crl.result,
	})

	return crl.revokedCertificates.map(({ userCertificate }) =>
		pvutils.bufferToHexCodes(userCertificate.valueBlock.valueHex)
	)
}

const readCertificateChain = (path) => {
	const content = fs.readFileSync(path)
	const contentString = Buffer.from(content).toString('ascii')

	// Drugi bug moze da nastane ovde, tako sto ne formiramo lepo niz
	const certificates = contentString
		.split('-----BEGIN CERTIFICATE-----')
		.map((c, i) => {
			if (i > 0) {
				return new X509Certificate('-----BEGIN CERTIFICATE-----' + c)
			}
			return null
		})
		.filter((e) => e)

	return certificates
}

const certificateDatesValid = (cert) => {
	return (
		Date.now() > Date.parse(cert.validFrom) &&
		Date.now() < Date.parse(cert.validTo)
	)
}

const verifyCertificateChain = (
	hostName,
	certificates,
	revokedCertificates,
	rootCertificates
) => {
	if (!certificates[0].checkHost(hostName)) {
		console.log('Invalid certificate: host is not valid.')
		return false
	}

	const result = certificates.reduce((acc, cert, i) => {
		if (!acc) {
			return false
		}

		// PROPUST 10
		// Ove provere nedostaju. Potrebno je validirati dozvoljenu duzinu putanje lanca za svaki sertifikat koji ima ogranicenje.
		// const maxPath = getBasicConstraintPathLength(cert)
		// if (i > 0 && i - 1 > maxPath) {
		// 	console.log(
		// 		`Certificate max path exceeded; Only ${maxPath} are allowed after certificate ${cert.subject}`
		// 	)
		// 	return false
		// }

		const validDates = certificateDatesValid(cert)
		if (!validDates) {
			console.log("Certificate has expired or didn't start")
			return false
		}

		if (i > 0 && certificates[i].subject !== certificates[i - 1].issuer) {
			console.log(
				'Invalid certificate chain; certificate subject is not issuer of previous.'
			)
			return false
		}

		if (i > 0 && !certificates[i - 1].checkIssued(cert)) {
			console.log(
				'Invalid certificate chain; certificate is not signed by the given issuer.'
			)
			return false
		}

		if (revokedCertificates.some((v) => cert.serialNumber === v)) {
			console.log('Invalid certificate; certificate has been revoked.')

			return false
		}

		const selfSigned = cert.issuer === cert.subject

		if (selfSigned && i !== certificates.length - 1) {
			console.log(
				'Invalid certificate; intermediate certificate cannot be self signed.'
			)
			return false
		}

		// Checks for last certificate in chain
		if (i === certificates.length - 1) {
			const issuer = cert.issuer

			const rootCAIssuer = rootCertificates.find(
				(cert) => cert.subject === issuer
			)

			if (!rootCAIssuer) {
				console.log('Invalid certificate; unable to find root CA')
				return false
			}

			if (selfSigned && rootCAIssuer.signature !== cert.signature) {
				console.log('Invalid certificate; unable to verify root CA')
				return false
			}

			if (!selfSigned && !cert.verify(rootCAIssuer.publicKey)) {
				console.log(
					'Invalid certificate chain; certificate is not signed by the given issuer.'
				)
				return false
			}
		}

		return acc
	}, true)

	console.log('Certificate is valid:', result)

	return result
}

const certificates = readCertificateChain('./certificates.pem')
const revokedCertificates = getRevocationListSerialNumbers('Omniroot2025.crl')
const rootCertificates = getRootCertificates()
verifyCertificateChain(
	'8gwifi.org',
	certificates,
	revokedCertificates,
	rootCertificates
)
