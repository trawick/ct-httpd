if test $# -ne 1; then
    echo "Usage: $0 {1|2}" 1>&2
    exit 1
fi

if test $1 -eq 1; then
    STORAGE=/tmp/logdb1
    CERT_FILE=testdata/ca-cert.pem
    KEY=testdata/ct-server-key.pem
    PORT=8888
else
    STORAGE=/tmp/logdb2
    CERT_FILE=testdata/ca-cert.pem
    KEY=testdata/ct-server-key.pem
    PORT=8889
fi

cd $HOME/git/certificate-transparency/src/test
../server/ct-rfc-server --port=$PORT \
                        --key=$KEY \
                        --trusted_cert_file=$CERT_FILE \
                        --logtostderr=true \
                        --tree_signing_frequency_seconds=5 \
                        --sqlite_db=$STORAGE \
                        --v=5
