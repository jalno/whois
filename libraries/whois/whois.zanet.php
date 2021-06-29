<?php
namespace packages\whois;
class zanet_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain.name' => 'Domain Name            : ',
            'domain.created' => 'Record Created         :',
            'domain.changed' => 'Record	Last Updated    :',
            'owner.name' => 'Registered for         :',
            'admin' => 'Administrative Contact :',
            'tech' => 'Technical Contact      :',
            'domain.nserver' => 'Domain Name Servers listed in order:',
            'registered' => 'No such domain: ',
            '' => 'The ZA NiC whois'
        );

        // Arrange contacts ...

        $rawdata = array();

        foreach ($data_str['rawdata'] as $key => $line) {
            if (strpos($line, ' Contact ') !== false) {
                $pos = strpos($line, ':');

                if ($pos !== false) {
                    $rawdata[] = substr($line, 0, $pos + 1);
                    $rawdata[] = trim(substr($line, $pos + 1));
                    continue;
                }
            }
            $rawdata[] = $line;
        }

        $r = array();
        $r['regrinfo'] = get_blocks($rawdata, $items);

        if (isset($r['regrinfo']['registered'])) {
            $r['regrinfo']['registered'] = 'no';
        } else {
            if (isset($r['regrinfo']['admin']))
                $r['regrinfo']['admin'] = get_contact($r['regrinfo']['admin']);

            if (isset($r['regrinfo']['tech']))
                $r['regrinfo']['tech'] = get_contact($r['regrinfo']['tech']);
        }

        $r['regyinfo']['referrer'] = 'http://www.za.net/'; // or http://www.za.org
        $r['regyinfo']['registrar'] = 'ZA NiC';
        format_dates($r, 'xmdxxy');
        return $r;
    }

}
