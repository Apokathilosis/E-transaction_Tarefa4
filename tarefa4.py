import os
import datetime
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509.extensions import ExtensionNotFound

def load_certificate_from_file(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
    return x509.load_pem_x509_certificate(cert_data, default_backend())

def download_certificate_from_aia(aia_url):
    try:
        response = requests.get(aia_url)
        response.raise_for_status()
        return x509.load_der_x509_certificate(response.content, default_backend())
    except Exception as e:
        print(f"Erro ao baixar certificado da URL {aia_url}: {e}")
        return None

def is_within_validity_period(cert):
    current_time = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = cert.not_valid_before_utc
    not_valid_after = cert.not_valid_after_utc
    return not_valid_before <= current_time <= not_valid_after

def check_revocation_crl(cert):
    try:
        crl_distribution_points = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        crl_url = crl_distribution_points.value[0].full_name[0].value
        response = requests.get(crl_url)
        crl = x509.load_der_x509_crl(response.content, default_backend())

        for revoked_cert in crl:
            if revoked_cert.serial_number == cert.serial_number:
                print("Certificado revogado encontrado na CRL.")
                return True
        return False
    except Exception:
        return False

def check_revocation_ocsp(cert, issuer_cert):
    try:
        aia_extension = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_url = next(
            (desc.access_location.value for desc in aia_extension.value
             if desc.access_method.dotted_string == "1.3.6.1.5.5.7.48.1"), None)
        
        if ocsp_url is None:
            print("OCSP URL não encontrada.")
            raise Exception

        builder = x509.ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
        ocsp_request = builder.build()

        headers = {'Content-Type': 'application/ocsp-request'}
        response = requests.post(ocsp_url, data=ocsp_request.public_bytes(), headers=headers)
        ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)

        if ocsp_response.response_status == x509.ocsp.OCSPResponseStatus.SUCCESSFUL:
            return ocsp_response.certificate_status == x509.ocsp.OCSPCertStatus.REVOKED
        else:
            return False

    except Exception:
        return False

def is_revoked(cert, issuer_cert=None):
    if issuer_cert and check_revocation_ocsp(cert, issuer_cert):
        print("Certificado foi revogado (OCSP).")
        return True
    elif check_revocation_crl(cert):
        print("Certificado foi revogado (CRL).")
        return True
    return False

def check_ski_aki_chain(cert, trusted_roots_folder):
    chain = [cert]
    current_cert = cert
    is_trusted = False

    while True:
        if is_revoked(current_cert):
            print("Certificado na cadeia foi revogado.")
            return False, chain

        if is_trusted_root(current_cert, trusted_roots_folder):
            is_trusted = True
            break

        try:
            aia_extension = current_cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            issuer_cert_url = None
            for access_desc in aia_extension.value:
                if access_desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    issuer_cert_url = access_desc.access_location.value
                    break
        except ExtensionNotFound:
            print("Cadeia incompleta ou não confiável: Extensão Authority Information Access ausente.")
            return False, chain

        next_cert = download_certificate_from_aia(issuer_cert_url)
        if not next_cert:
            print("Não foi possível obter o certificado do próximo nível na cadeia. Cadeia incompleta.")
            return False, chain

        if is_revoked(next_cert, current_cert):
            print("Certificado na cadeia foi revogado.")
            return False, chain

        chain.append(next_cert)
        current_cert = next_cert

    return is_trusted, chain

def is_trusted_root(cert, trusted_roots_folder):
    for root_filename in os.listdir(trusted_roots_folder):
        root_path = os.path.join(trusted_roots_folder, root_filename)
        root_cert = load_certificate_from_file(root_path)
        try:
            cert_ski = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
            root_cert_ski = root_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
            if cert_ski == root_cert_ski:
                return True
        except ExtensionNotFound:
            continue
    return False

def validate_certificate_chain(end_entity_cert_path, trusted_roots_folder):
    end_entity_cert = load_certificate_from_file(end_entity_cert_path)

    if not is_within_validity_period(end_entity_cert):
        print("Certificado final fora do período de validade.")
        return False
    
    is_trusted, chain = check_ski_aki_chain(end_entity_cert, trusted_roots_folder)
    if not is_trusted:
        print("A cadeia de certificação não é confiável ou está incompleta.")
        return False
    else:
        print("A cadeia de certificação é confiável e completa.")
        print("Cadeia de certificação:")
        for cert in chain:
            print(f"- {cert.subject.rfc4514_string()}")

def main():
    # Caminhos para o certificado do usuário e a pasta de certificados confiáveis
    extension = input("Digite a extensão do certificado (cer ou crt): ").strip().lower()
    while extension not in ["cer", "crt"]:
        print("Extensão inválida. Escolha entre cer ou crt.")
        extension = input("Digite a extensão do certificado (cer ou crt): ").strip().lower()

    # Solicita ao usuário o nome do arquivo sem a extensão
    filename = input("Digite o nome do arquivo de certificado (sem a extensão): ").strip()
    base_path = "verificar"
    end_entity_cert_path = os.path.join(base_path, f"{filename}.{extension}")
    trusted_roots_folder = "trusted_root"

    # Executa a validação da cadeia
    validate_certificate_chain(end_entity_cert_path, trusted_roots_folder)

if __name__ == "__main__":
    main()