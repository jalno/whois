<?php
namespace packages\whois;
class alldomains_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative',
            'tech' => 'Technical',
            'domain.name' => 'Domain name:',
            'domain.sponsor' => 'Registrar:',
            'domain.nserver.' => 'Domain servers in listed order:'
        );

        return easy_parser($data_str, $items, 'ymd');
    }

}
