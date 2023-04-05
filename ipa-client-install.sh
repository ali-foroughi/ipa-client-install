#!/bin/bash
echo ""
echo "*** Configuring IPA client on Debian 11 ***"
echo ""

### These values can be changed: 
IPA="ipa.zcore.local"
DOMAIN="zcore.local"
NS1=172.20.11.12
NS2=172.20.11.11

#### functions ####

### ssh -o PubkeyAuthentication=yes -o PasswordAuthentication=no -o StrictHostKeyChecking=no root@ipa.zcore.local

#ssh -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa.pub root@ipa.zcore.local

DOMAIN_UP=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')

check_failure () {
RESULT=$?
if [ $RESULT != 0 ]; then
    echo "an error has occured. Exiting script."
    exit 1;
fi
}

check_input () {
if [ -z "$CLIENT_NAME" ] || [ -z "$CLIENT_IP" ] 
then 
    echo 'Inputs cannot be blank please try again!' 
    exit 0 
fi 
}

check_pkg ()
{
    packages=("sssd" "sssd-tools" "libnss-sss" "libpam-sss" "ca-certificates" "krb5-user" "libnss3-tools" "libsss-sudo")
    for package in "${packages[@]}"
    do
        if ! dpkg -l "$package" > /dev/null 2>&1; then
            echo "$package is not installed."
        else
            printf "\xE2\x9C\x94 $package installed\n"
        fi
    done
}

check_ipa_access ()
{
    CHECK_KEY=$(ssh -o PubkeyAuthentication=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa.pub root@$IPA 2>&1)

    if [[ $CHECK_KEY == *"Permission denied"* ]]; then

        echo "ERROR: Public key authentication to the IPA server failed. Please make sure you have access and try again."
        exit 1;
    else
        printf "\xE2\x9C\x94 Access to IPA server confirmed\n"
    fi
}


#### Ask of user to specifiy client name and IP address ###

read -p 'Specifiy client name (e.g srv15-mme-1): ' CLIENT_NAME
read -p 'Specifiy the client IP: ' CLIENT_IP
check_input

##### verify client name and IP adderss ### 
echo ""
echo -e "Please verify the information: \nClient Name: $CLIENT_NAME \nServer IP: $CLIENT_IP"
echo ""
read -p "Contiue? (y/n): " INFO_VERIFY
echo ""

if [ $INFO_VERIFY == "n" ]
then
    echo "Canceling configuration. Exiting"
    exit 0
fi


# Configure HTTP proxy for APT

while true; do
    read -p 'Do you want to configure an HTTP proxy for package installation? (y/n) ' yn
    case $yn in
        [Yy]* )
            read -p "Please enter HTTP/HTTPS proxy IP address: " PROXY_IP
            read -p "Please enter the port for the proxy: " PROXY_PORT
            if ! grep -rwq '^Acquire::http' /etc/apt/; then
                echo "Acquire::http { Proxy \"http://$PROXY_IP:$PROXY_PORT\"; };" > /etc/apt/apt.conf.d/00proxy
                echo "Acquire::https { Proxy \"http://$PROXY_IP:$PROXY_PORT\"; };" >> /etc/apt/apt.conf.d/00proxy
            else
                echo "Proxy already configured."
            fi
            break;;
        [Nn]* ) echo "Continuing..."
        break;;
        * ) echo "Please answer yes or no.";;
    esac
done

check_ipa_access

#add nameserver 172.20.11.12 to /etc/resolv.conf

if ! grep -rnwq $NS1 /etc/resolv.conf || ! grep -rnwq $NS2 /etc/resolv.conf
then
    sed -i '1s/^/nameserver '$NS1'\n/' /etc/resolv.conf
    sed -i '1s/^/nameserver '$NS2'\n/' /etc/resolv.conf

    echo "===> Added nameservers to /etc/resolv.conf"
else
    printf "\xE2\x9C\x94 Nameservers already configured\n"
fi

### set hostname
if [[ $(hostname) != "$CLIENT_NAME.$DOMAIN" ]]
then
    hostnamectl set-hostname $CLIENT_NAME.$DOMAIN
    echo "===> Configuring hostname"
else
    printf "\xE2\x9C\x94 Hostname is correct\n"
fi

HOSTNAME=$(hostname)

#Add hostname and IP entry to /etc/hosts
if ! grep -rwq $(hostname) /etc/hosts
then
    echo "$CLIENT_IP    $HOSTNAME" >> /etc/hosts
    echo "===> Copied IP and hostname to /etc/hosts"
else
    printf "\xE2\x9C\x94 IP and hostname found in /etc/hosts\n"
fi


echo ""
echo "===> checking connection to IPA server"
echo ""
ping -c 3 $IPA
check_failure

echo ""
echo "===> checking correct configuration of hostname"
echo ""
ping -c 3 $HOSTNAME
check_failure

echo ""
echo "===> Installing required packages ..."
echo ""
sleep 3


#install packages
apt-get update
apt-get install -y sssd sssd-tools libnss-sss libpam-sss ca-certificates krb5-user libnss3-tools libsss-sudo
check_pkg

#copy sssd file /etc/sssd/sssd.conf and make changes 
mkdir -p /etc/sssd/
cp config_files/sssd.conf /etc/sssd
sed -i "s/IPA_SERVER/$IPA/g" /etc/sssd/sssd.conf
sed -i "s/IPA_DOMAIN/$DOMAIN/g" /etc/sssd/sssd.conf
sed -i "s/HOSTNAME/$HOSTNAME/g" /etc/sssd/sssd.conf
chmod 600 /etc/sssd/sssd.conf
printf "\xE2\x9C\x94 SSSD configuration complete\n"

#copy the /etc/ipa/ca.crt file
mkdir -p /etc/ipa/
cp config_files/ca.crt /etc/ipa

#copy /etc/ipa/nssdb/pwdfile.txt
mkdir -p /etc/ipa/nssdb
cp config_files/pwdfile.txt /etc/ipa/nssdb

/usr/bin/certutil -d /etc/ipa/nssdb -N -f /etc/ipa/nssdb/pwdfile.txt -@ /etc/ipa/nssdb/pwdfile.txt

printf "\xE2\x9C\x94 nssdb database created\n"


#copy the /etc/ldap/ldap.conf file
mkdir -p /etc/ldap/
cp config_files/ldap.conf /etc/ldap

DC_1=$(echo $IPA | rev | cut -d "." -f 1 | rev)
DC_2=$(echo $IPA | rev | cut -d "." -f 2 | rev)
sed -i "s/LDAP_SERVER/$IPA/g" /etc/ldap/ldap.conf
sed -i "s/DC_2/$DC_2/g" /etc/ldap/ldap.conf
sed -i "s/DC_1/$DC_1/g" /etc/ldap/ldap.conf

printf "\xE2\x9C\x94 LDAP configuration complete\n"

# copy /etc/nsswitch.conf
cp config_files/nsswitch.conf /etc

#add ca.crt file to the end of /etc/ssl/certs/ca-certificates.crt
echo "##### $DOMAIN CA CERT ######" >> /etc/ssl/certs/ca-certificates.crt
cat /etc/ipa/ca.crt >> /etc/ssl/certs/ca-certificates.crt

echo ""
echo "===> SSH into IPA server ..."
echo ""

ssh root@$IPA <<EOL
ipa host-add --force --ip-address=$CLIENT_IP $HOSTNAME
rm -f /root/krb5.keytab
ipa-getkeytab -s ipa.zcore.local -p host/$HOSTNAME@ZCORE.LOCAL -k /root/krb5.keytab
EOL


sleep 2
scp root@$IPA:/root/krb5.keytab /etc

printf "\xE2\x9C\x94 keytab copied from IPA server\n"

#copy /etc/krb5.conf and replace the domain name in the file
cp config_files/krb5.conf /etc
sed -i "s/HOSTNAME/$HOSTNAME/g" /etc/krb5.conf
sed -i "s/DOMAIN_UP/$DOMAIN_UP/g" /etc/krb5.conf
sed -i "s/DOMAIN/$DOMAIN/g" /etc/krb5.conf


#copy the contents of /var/lib/ipa-client/pki/kdc-ca-bundle.pem
mkdir -p /var/lib/ipa-client/pki/
scp -o StrictHostKeyChecking=no root@$IPA:/var/lib/ipa-client/pki/kdc-ca-bundle.pem /var/lib/ipa-client/pki
scp -o StrictHostKeyChecking=no root@$IPA:/var/lib/ipa-client/pki/ca-bundle.pem /var/lib/ipa-client/pki

#create the directory /etc/krb5.conf.d and copy the file /etc/krb5.conf.d/freeipa
mkdir -p /etc/krb5.conf.d
cp config_files/freeipa /etc/krb5.conf.d

# Adding mkhomedir to the PAM configuration

if ! grep -rwq "pam_mkhomedir.so" /etc/pam.d/common-session
then
    echo "session optional           pam_mkhomedir.so" >> /etc/pam.d/common-session
    printf "\xE2\x9C\x94 PAM configuration complete\n"
else
    printf "\xE2\x9C\x94 PAM configuration confirmed\n"
fi


#make backup of SSH configuration
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cp /etc/ssh/ssh_config /etc/ssh/ssh_config.bak

#Copying ssh configration
cp config_files/sshd_config /etc/ssh
cp config_files/ssh_config /etc/ssh

echo ""
echo "===> Restarting services ..."
sleep 3

#Restart services

systemctl restart sssd.service
systemctl restart sshd.service
systemctl restart graylog-sidecar

printf "\xE2\x9C\x94 Services restarted and ready\n"

#enable APT proxy
#sed -i 's/#Acquire/Acquire/g' /etc/apt/apt.conf

# Disalce Apprmor notifications for SSSD
ln -sf /etc/apparmor.d/usr.sbin.sssd /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/usr.sbin.sssd
printf "\xE2\x9C\x94 Apparmor disabled\n"
echo ""
printf "\xE2\x9C\x85 PAM Setup complete\n"
echo ""
