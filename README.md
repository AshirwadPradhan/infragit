# InfraGIT
## A SaaS secure VCS (based on Git) for confidential repositories. 





##### Note :- Add CA's public key to Trusted Root Certificates if you face any 'Invalid CA certificate' issue (required for Microsoft Windows 10)


##### Run Server : `uwsgi --master --https localhost:5683,server-public-key.pem,server-private-key.pem --mount /=gateway:app`
 --Enter secret for server private key when asked