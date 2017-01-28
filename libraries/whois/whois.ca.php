<?php
namespace packages\whois;
class ca_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative contact:',
            'tech' => 'Technical contact:',
            'domain.sponsor' => 'Registrar:',
            'domain.nserver' => 'Name servers:',
            'domain.status' => 'Domain status:',
            'domain.created' => 'Creation date:',
            'domain.expires' => 'Expiry date:',
            'domain.changed' => 'Updated date:'
        );

        $extra = array(
            'postal address:' => 'address.0',
            'job title:' => '',
            'number:' => 'handle',
            'description:' => 'organization'
        );

        $r = array();
        $r['regrinfo'] = easy_parser($data_str['rawdata'], $items, 'ymd', $extra);

        if (!empty($r['regrinfo']['domain']['sponsor'])) {
            list($v, $reg) = explode(':', $r['regrinfo']['domain']['sponsor'][0]);
            $r['regrinfo']['domain']['sponsor'] = trim($reg);
        }

        if (empty($r['regrinfo']['domain']['status']) || $r['regrinfo']['domain']['status'] == 'available')
            $r['regrinfo']['registered'] = 'no';
        else
            $r['regrinfo']['registered'] = 'yes';

        $r['regyinfo'] = array(
            'registrar' => 'CIRA',
            'referrer' => 'http://www.cira.ca/'
        );
        return $r;
    }

}
