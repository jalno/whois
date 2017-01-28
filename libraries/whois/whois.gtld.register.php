<?php
namespace packages\whois;
class register_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner#0' => 'Registrant Info:',
            'owner#1' => 'Organization:',
            'owner#2' => 'Registrant:',
            'owner#3' => 'Registrant Contact:',
            'admin' => 'Administrative',
            'tech' => 'Technical',
            'zone' => 'Zone',
            'domain.sponsor#0' => 'Registrar Name....:',
            'domain.sponsor#1' => 'Registration Service Provided By:',
            'domain.referrer' => 'Registrar Homepage:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.nserver' => 'DNS Servers:',
            'domain.name' => 'Domain name:',
            'domain.created#0' => 'Created on..............:',
            'domain.created#1' => 'Creation date:',
            'domain.expires#0' => 'Expires on..............:',
            'domain.expires#1' => 'Expiration date:',
            'domain.changed' => 'Record last updated on..:',
            'domain.status' => 'Status:'
        );

        return easy_parser($data_str, $items, 'ymd');
    }

}
