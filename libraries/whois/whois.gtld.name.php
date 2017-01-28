<?php
namespace packages\whois;
class name_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'REGISTRANT CONTACT INFO',
            'admin' => 'ADMINISTRATIVE CONTACT INFO',
            'tech' => 'TECHNICAL CONTACT INFO',
            'billing' => 'BILLING CONTACT INFO',
            'domain.name' => 'Domain Name:',
            'domain.sponsor' => 'Registrar',
            'domain.created' => 'Creation Date',
            'domain.expires' => 'Expiration Date'
        );

        $extra = array(
            'phone:' => 'phone',
            'email address:' => 'email'
        );

        return easy_parser($data_str, $items, 'y-m-d', $extra, false, true);
    }

}
