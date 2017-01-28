<?php
namespace packages\whois;
class namevault_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'billing' => 'Billing Contact:',
            'domain.name' => 'Domain Name:',
            'domain.nserver.' => 'Name Servers',
            'domain.created' => 'Creation Date:',
            'domain.expires' => 'Expiration Date:',
            'domain.status' => 'Status:'
        );

        return easy_parser($data_str, $items, 'dmy', array(), true, true);
    }

}
