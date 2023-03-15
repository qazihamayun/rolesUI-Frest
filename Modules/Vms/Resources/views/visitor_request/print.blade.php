<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="style.css">
    <title>Vistor Print</title>
    <style>
        * {
            font-size: 12px;
            font-family: 'Times New Roman';
        }

        td,
        th,
        tr,
        table {
            border-top: 1px solid black;
            border-collapse: collapse;
        }

        td.description,
        th.description {
            width: 75px;
            max-width: 75px;
        }

        td.quantity,
        th.quantity {
            width: 40px;
            max-width: 40px;
            word-break: break-all;
        }

        td.price,
        th.price {
            width: 40px;
            max-width: 40px;
            word-break: break-all;
        }

        .centered {
            text-align: center;
            align-content: center;
        }

        .ticket {
            width: 155px;
            max-width: 155px;
        }

        img {
            max-width: inherit;
            width: inherit;
        }

        @media print {

            .hidden-print,
            .hidden-print * {
                display: none !important;
            }
        }
    </style>
</head>

<body>
    <div class="ticket">
        <div class="centered">
            {!! QrCode::size(100)->generate($visitor->id) !!}
        </div>

        <!-- <img src="{{ asset('assets/img/logo.png') }}" alt="Logo"> -->

        <H3 class="centered">Visitor Managment
            <br>System (VMS)
        </H3>
        <table>
            <thead>

                <tr>
                    <th class="quantity">Name</th>
                    <th colspan="2">{{ UcFirst($visitor->user->name) }}</th>

                </tr>
            </thead>
            <tbody>
                <tr>
                    <th class="quantity">Status</th>
                    <th colspan="1">Approved</th>
                </tr>
                <tr>
                    <th class="quantity">Dept</th>
                    <th colspan="2">{{ UcFirst($visitor->department->title) }}</th>
                </tr>

                <tr>
                    <th class="quantity">CNIC</th>
                    <th colspan="2">{{ UcFirst($visitor->user->cnic) }}</th>
                </tr>
                <tr>
                    <th class="quantity">Date</th>
                    <th colspan="2">{{ $visitor->created_at->format('d/m/y') }}</th>
                </tr>

            </tbody>
        </table>
        <p class="centered">Thanks for your Cooperation!
        </p>
    </div>
    <button id="btnPrint" class="hidden-print">Print</button>
    <a href="{{ route('my.dashboard') }}" class="hidden-print">back</a>
    <script>
        const $btnPrint = document.querySelector("#btnPrint");
        $btnPrint.addEventListener("click", () => {
            window.print();
        });
    </script>
</body>

</html>
