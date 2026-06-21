target := "x86_64-unknown-linux-gnu"
binary := "pitopi"
user := "root"

build:
    cargo -q build

release:
    cargo -q build --release

cross:
    cross -q build --release --target {{target}}

deploy ip:
    cross -q build --release --target {{target}}
    rsync -az --progress target/{{target}}/release/{{binary}} {{user}}@{{ip}}:/tmp/
    ssh {{user}}@{{ip}} "getent group pitopi >/dev/null || groupadd pitopi && install -m 755 /tmp/{{binary}} /usr/local/bin/{{binary}} && {{binary}} install-service && systemctl daemon-reload && systemctl enable pitopi && systemctl restart pitopi"
    @echo "Deployed and installed daemon on {{ip}}"

deploy-dev ip:
    cross -q build --target {{target}}
    rsync -az --progress target/{{target}}/debug/{{binary}} {{user}}@{{ip}}:/tmp/
    ssh {{user}}@{{ip}} "getent group pitopi >/dev/null || groupadd pitopi && install -m 755 /tmp/{{binary}} /usr/local/bin/{{binary}} && {{binary}} install-service && systemctl daemon-reload && systemctl enable pitopi && systemctl restart pitopi"
    @echo "Deployed and installed daemon on {{ip}} (debug build)"

check:
    cargo -q check

run *args:
    sudo cargo -q run -- {{args}}
