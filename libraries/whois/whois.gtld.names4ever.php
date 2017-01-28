<?php
namespace packages\whois;
class names4ever_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact',
            'tech' => 'Technical  Contact',
            'domain.name' => 'Domain Name:',
            'domain.sponsor' => 'Registrar Name....:',
            'domain.referrer' => 'Registrar Homepage:',
            'domain.nserver' => 'DNS Servers:',
            'domain.created' => 'Record created on',
            'domain.expires' => 'Record expires on',
            'domain.changed' => 'Record last updated on',
            'domain.status' => 'Domain status:'
        );

        return easy_parser($data_str, $items, 'dmy', array(), false, true);
    }

}
