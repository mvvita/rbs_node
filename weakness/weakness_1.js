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
	// PROPUST 1
	if (!certificates[0].checkHost(hostName)) {
		console.log('Invalid certificate: host is not valid.')
		return false
	}

	const validDates = certificateDatesValid(certificates[0])
	if (!validDates) {
		console.log("Certificate has expired or didn't start")
		return false
	}

	console.log('Certificate is valid:', true)

	return true
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
