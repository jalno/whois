<?php
namespace packages\whois;
class co_Za_handler {

    function parse($data_str, $query) {
        $items = array(
            '0a. lastupdate             :' => 'domain.changed',
            '1a. domain                 :' => 'domain.name',
            '2b. registrantpostaladdress:' => 'owner.address.address.0',
            '2f. billingaccount         :' => 'billing.name',
            '2g. billingemail           :' => 'billing.email',
            '2i. invoiceaddress         :' => 'billing.address',
            '2j. registrantphone        :' => 'owner.phone',
            '2k. registrantfax          :' => 'owner.fax',
            '2l. registrantemail        :' => 'owner.email',
            '4a. admin                  :' => 'admin.name',
            '4c. admincompany           :' => 'admin.organization',
            '4d. adminpostaladdr        :' => 'admin.address',
            '4e. adminphone             :' => 'admin.phone',
            '4f. adminfax               :' => 'admin.fax',
            '4g. adminemail             :' => 'admin.email',
            '5a. tec                    :' => 'tech.name',
            '5c. teccompany             :' => 'tech.organization',
            '5d. tecpostaladdr          :' => 'tech.address',
            '5e. tecphone               :' => 'tech.phone',
            '5f. tecfax                 :' => 'tech.fax',
            '5g. tecemail               :' => 'tech.email',
            '6a. primnsfqdn             :' => 'domain.nserver.0',
            '6e. secns1fqdn             :' => 'domain.nserver.1',
            '6i. secns2fqdn             :' => 'domain.nserver.2',
            '6m. secns3fqdn             :' => 'domain.nserver.3',
            '6q. secns4fqdn             :' => 'domain.nserver.4'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items);

        $r['regyinfo']['referrer'] = 'http://www.co.za';
        $r['regyinfo']['registrar'] = 'UniForum Association';
        return $r;
    }

}
