<?php
namespace packages\whois;
class godaddy_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact',
            'tech' => 'Technical Contact',
            'domain.name' => 'Domain Name:',
            'domain.nserver.' => 'Domain servers in listed order:',
            'domain.created' => 'Created on:',
            'domain.expires' => 'Expires on:',
            'domain.changed' => 'Last Updated on:',
            'domain.sponsor' => 'Registered through:'
        );

        $r = get_blocks($data_str, $items);
        $r['owner'] = get_contact($r['owner']);
        $r['admin'] = get_contact($r['admin'], array(), true);
        $r['tech'] = get_contact($r['tech'], array(), true);
        return format_dates($r, 'dmy');
    }

}
