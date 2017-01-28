<?php
namespace packages\whois;
class fj_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'domain.status' => 'Status:',
            'domain.expires' => 'Expires:',
            'domain.nserver' => 'Domain servers:'
        );

        $r = array();
        $r['regrinfo'] = get_blocks($data_str['rawdata'], $items);

        if (!empty($r['regrinfo']['domain']['status'])) {
            $r['regrinfo'] = get_contacts($r['regrinfo']);

            date_default_timezone_set("Pacific/Fiji");

            if (isset($r['regrinfo']['domain']['expires']))
                $r['regrinfo']['domain']['expires'] = strftime("%Y-%m-%d", strtotime($r['regrinfo']['domain']['expires']));

            $r['regrinfo']['registered'] = 'yes';
        } else {
            $r['regrinfo']['registered'] = 'no';
        }

        $r['regyinfo'] = array(
            'referrer' => 'http://www.domains.fj',
            'registrar' => 'FJ Domain Name Registry'
        );
        return $r;
    }

}
