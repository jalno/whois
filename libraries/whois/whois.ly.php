<?php
namespace packages\whois;
class ly_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'domain.name' => 'Domain Name:',
            'domain.status' => 'Domain Status:',
            'domain.created' => 'Created:',
            'domain.changed' => 'Updated:',
            'domain.expires' => 'Expired:',
            'domain.nserver' => 'Domain servers in listed order:'
        );

        $extra = array('zip/postal code:' => 'address.pcode');

        $r = array();
        $r['regrinfo'] = get_blocks($data_str['rawdata'], $items);

        if (!empty($r['regrinfo']['domain']['name'])) {
            $r['regrinfo'] = get_contacts($r['regrinfo'], $extra);
            $r['regrinfo']['domain']['name'] = $r['regrinfo']['domain']['name'][0];
            $r['regrinfo']['registered'] = 'yes';
        } else {
            $r = array('regrinfo' => array());
            $r['regrinfo']['registered'] = 'no';
        }

        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.ly',
            'registrar' => 'Libya ccTLD'
        );
        return $r;
    }

}
