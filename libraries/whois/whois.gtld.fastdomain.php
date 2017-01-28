<?php
namespace packages\whois;
class fastdomain_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant Info:',
            'admin' => 'Administrative Info:',
            'tech' => 'Technical Info:',
            'domain.name' => 'Domain Name:',
            'domain.sponsor' => 'Provider Name....:',
            'domain.referrer' => 'Provider Homepage:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.created' => 'Created on..............:',
            'domain.expires' => 'Expires on..............:',
            'domain.changed' => 'Last modified on........:',
            'domain.status' => 'Status:'
        );

        while (list($key, $val) = each($data_str)) {
            $faststr = strpos($val, ' (FAST-');
            if ($faststr)
                $data_str[$key] = substr($val, 0, $faststr);
        }

        $r = easy_parser($data_str, $items, 'dmy', array(), false, true);

        if (isset($r['domain']['sponsor']) && is_array($r['domain']['sponsor']))
            $r['domain']['sponsor'] = $r['domain']['sponsor'][0];

        if (isset($r['domain']['nserver'])) {
            reset($r['domain']['nserver']);

            while (list($key, $val) = each($r['domain']['nserver'])) {
                if ($val == '=-=-=-=')
                    unset($r['domain']['nserver'][$key]);
            }
        }

        return $r;
    }

}
