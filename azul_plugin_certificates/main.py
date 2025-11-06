"""Inspects PEM encoded certificates and breaks it down into the X.509 components."""

from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)

# imports for x509 parsing
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12


class AzulPluginCertificates(BinaryPlugin):
    """Inspects PEM encoded certificates and breaks it down into the X.509 components."""

    VERSION = "2025.09.16"
    SETTINGS = add_settings(
        # Only select text files and unknown
        filter_data_types={"content": ["text/", "unknown"]},
        # Max file size 100MB
        filter_max_content_size="10MiB",
    )
    # Add cert_type feature
    FEATURES = [
        Feature("certificate_type", desc="The type of Certificate Detected", type=FeatureType.String),
        Feature("subject_name", desc="Subject's Common Name", type=FeatureType.String),
        Feature("subject_organisation", desc="Subject's Organisation Name", type=FeatureType.String),
        Feature("alt_name", desc="Subject's Alternate Name", type=FeatureType.String),
        Feature("issuer_organisation", desc="Issuer's Organisation Name", type=FeatureType.String),
        Feature("issuer_name", desc="Issuer's Common Name", type=FeatureType.String),
        Feature("serial_number", desc="Certificate's Serial Number", type=FeatureType.String),
        Feature("valid_from", desc="DateTime the Certificate is Valid From", type=FeatureType.Datetime),
        Feature("valid_to", desc="DateTime the Certificate is Valid To", type=FeatureType.Datetime),
    ]

    def parse_certificate(self, certificate, is_p7b=bool):
        """Take in a certificate/s and assigns feature values to the instance."""
        # is_p7b=True -> iteratively process the certificate chain
        # is_p7b=False -> treats the certificate as a stand-alone certificate
        # required variables for parsing
        subject_name = subject_org = alt_name = issuer_org = issuer_name = serial_number = ""
        valid_from = valid_to = ""

        if is_p7b:
            index = 0
            for cert in certificate:
                # Subject Related:
                for value in list(cert.subject):
                    if value.oid._name == "commonName":
                        subject_name = value._value
                    elif value.oid._name == "organizationName":
                        subject_org = value._value

                # Issuer Related:
                for value in list(cert.issuer):
                    if value.oid._name == "commonName":
                        issuer_name = value._value
                    elif value.oid._name == "organizationName":
                        issuer_org = value._value

                # Serial Number:
                serial_number = str(cert.serial_number)

                # Relevant Extensions (currently just alternate name):
                for extension in cert.extensions:
                    if extension.oid._name == "subjectAltName":
                        alt_name = str(extension.value[0].value)

                # Dates valid from & to :
                valid_from = cert.not_valid_before_utc
                valid_to = cert.not_valid_after_utc

                # Filling feature values for each detected certificate
                if subject_name:
                    self.add_feature_values("subject_name", FV(subject_name, label=("chain_index: " + str(index))))
                if subject_org:
                    self.add_feature_values(
                        "subject_organisation", FV(subject_org, label=("chain_index: " + str(index)))
                    )
                if alt_name:
                    self.add_feature_values("alt_name", FV(alt_name, label=("chain_index: " + str(index))))
                if issuer_org:
                    self.add_feature_values(
                        "issuer_organisation", FV(issuer_org, label=("chain_index: " + str(index)))
                    )
                if issuer_name:
                    self.add_feature_values("issuer_name", FV(issuer_name, label=("chain_index: " + str(index))))
                if serial_number:
                    self.add_feature_values("serial_number", FV(serial_number, label=("chain_index: " + str(index))))
                if valid_from:
                    self.add_feature_values("valid_from", FV(valid_from, label=("chain_index: " + str(index))))
                if valid_to:
                    self.add_feature_values("valid_to", FV(valid_to, label=("chain_index: " + str(index))))
                index += 1

        else:
            # Subject Related:
            for value in list(certificate.subject):
                if value.oid._name == "commonName":
                    subject_name = value._value
                elif value.oid._name == "organizationName":
                    subject_org = value._value

            # Issuer Related:
            for value in list(certificate.issuer):
                if value.oid._name == "commonName":
                    issuer_name = value._value
                elif value.oid._name == "organizationName":
                    issuer_org = value._value

            # Serial Number:
            serial_number = str(certificate.serial_number)

            # Relevant Extensions (currently just alternate name):
            for extension in certificate.extensions:
                if extension.oid._name == "subjectAltName":
                    alt_name = str(extension.value[0].value)

            # Dates valid from & to :
            valid_from = certificate.not_valid_before_utc
            valid_to = certificate.not_valid_after_utc

            # Filling feature values for certificate instance
            if subject_name:
                self.add_feature_values("subject_name", subject_name)
            if subject_org:
                self.add_feature_values("subject_organisation", subject_org)
            if alt_name:
                self.add_feature_values("alt_name", alt_name)
            if issuer_org:
                self.add_feature_values("issuer_organisation", issuer_org)
            if issuer_name:
                self.add_feature_values("issuer_name", issuer_name)
            if serial_number:
                self.add_feature_values("serial_number", serial_number)
            if valid_from:
                self.add_feature_values("valid_from", valid_from)
            if valid_to:
                self.add_feature_values("valid_to", valid_to)
        return

    def execute(self, job: Job):
        """Run the plugin."""
        buf = job.get_data().read()
        # LIST OF CERT TYPES
        certificate_types = ["PEM", "DER", "PKCS#7(PEM)", "PKCS#7(DER)", "PKCS#12"]

        """Functions handling checking and parsing for different file types"""

        def load_pem(buffer) -> bool:
            """Attempt to load certificate from .pem file, if successful: parse the x.509 components."""
            try:
                buffer = x509.load_pem_x509_certificate(buffer, default_backend())
                self.parse_certificate(buffer, False)
                self.add_feature_values("certificate_type", "PEM")
                return True
            except Exception:
                return False

        def load_der(buffer) -> bool:
            """Attempt to load certificate from .der file, if successful: parse the x.509 components."""
            try:
                pem_data = x509.load_der_x509_certificate(buf).public_bytes(encoding=serialization.Encoding.PEM)
                buffer = x509.load_pem_x509_certificate(pem_data, default_backend())
                self.parse_certificate(buffer, False)
                self.add_feature_values("certificate_type", "DER")
                return True
            except Exception:
                return False

        def load_pkcs7_pem(buffer) -> bool:
            """Attempt to load certificate from .pem PKCS7 file, if successful: parse the x.509 components."""
            try:
                p7b_obj = pkcs7.load_pem_pkcs7_certificates(buffer)
                self.parse_certificate(p7b_obj, True)
                self.add_feature_values("certificate_type", "PKCS#7(PEM)")
                return True
            except Exception:
                return False

        def load_pkcs7_der(buffer) -> bool:
            """Attempt to load certificate from .der PKCS7 file, if successful: parse the x.509 components."""
            try:
                p7b_obj = pkcs7.load_der_pkcs7_certificates(buffer)
                self.parse_certificate(p7b_obj, True)
                self.add_feature_values("certificate_type", "PKCS#7(DER)")
                return True
            except Exception:
                return False

        def load_pkcs12(buffer) -> bool:
            """Attempt to load certificate from PKCS12 file, if successful: parse the x.509 components."""
            try:
                _, certificate, _ = pkcs12.load_key_and_certificates(buffer, None)
                self.parse_certificate(certificate, False)
                self.add_feature_values("certificate_type", "PKCS#12")
                return True
            except Exception:
                return False

        parse_func_dict = {
            "PEM": load_pem(buf),
            "DER": load_der(buf),
            "PKCS#7(PEM)": load_pkcs7_pem(buf),
            "PKCS#7(DER)": load_pkcs7_der(buf),
            "PKCS#12": load_pkcs12(buf),
        }

        for cert_type in certificate_types:
            successful_parse = parse_func_dict[cert_type]
            if successful_parse:
                break

        # If no valid file type is detected and parsed, opt out
        if not successful_parse:
            return State(
                State.Label.OPT_OUT,
                message="Suitable Certificate file not detected..",
            )
        else:
            return


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginCertificates)


if __name__ == "__main__":
    main()
