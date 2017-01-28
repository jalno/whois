<?php
namespace packages\whois;
class mx_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'billing' => 'Billing Contact:',
            'domain.nserver' => 'Name Servers:',
            'domain.created' => 'Created On:',
            'domain.expires' => 'Expiration Date:',
            'domain.changed' => 'Last Updated On:',
            'domain.sponsor' => 'Registrar:'
        );

        $extra = array(
            'city:' => 'address.city',
            'state:' => 'address.state',
            'dns:' => '0'
        );

        $r = array();
        $r['regrinfo'] = easy_parser($data_str['rawdata'], $items, 'dmy', $extra);

        $r['regyinfo'] = array(
            'registrar' => 'NIC Mexico',
            'referrer' => 'http://www.nic.mx/'
        );

        if (empty($r['regrinfo']['domain']['created']))
            $r['regrinfo']['registered'] = 'no';
        else
            $r['regrinfo']['registered'] = 'yes';

        return $r;
    }

}
