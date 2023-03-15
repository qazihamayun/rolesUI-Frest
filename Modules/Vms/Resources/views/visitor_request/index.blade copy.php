@extends('layouts.app_screen_frest_vms')
@php $app_id = config('vms.app_id') @endphp


@section('content')
<div class="row ">
    <div class="col-lg-3 col-md-6 col-sm-6 mb-4">
        <div class="card">
            <a href="{{ route('enduservisit.create') }}">

                <div class="card-body">
                    <div class="d-flex justify-content-between">
                        <div class="d-flex align-items-center gap-3">
                            <div class="avatar">
                                <span class="avatar-initial rounded-circle bg-label-primary"><i class="bx bx-user fs-4"></i></span>
                            </div>
                            <div class="card-info">
                                <h5 class="card-title mb-0 ">{{ $requested }}</h5>
                                <small class="text-muted"> New</small>
                            </div>
                        </div>
                        <div id="conversationChart"></div>
                    </div>
                </div>
            </a>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 col-sm-6 mb-4">
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div class="d-flex align-items-center gap-3">
                        <div class="avatar">
                            <span class="avatar-initial rounded-circle bg-label-warning"><i class="bx bx-user-check fs-4"></i></span>
                        </div>
                        <div class="card-info">
                            <h5 class="card-title mb-0">{{ $accept }}</h5>
                            <small class="text-muted">Accepted</small>
                        </div>
                    </div>
                    <div id="incomeChart"></div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 col-sm-6 mb-4">
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div class="d-flex align-items-center gap-3">
                        <div class="avatar">
                            <span class="avatar-initial rounded-circle bg-label-success"><i class="bx bxs-user-detail fs-4"></i></span>
                        </div>
                        <div class="card-info">
                            <h5 class="card-title mb-0 me-2">{{ $visited }}</h5>
                            <small class="text-muted">lastVisit</small>
                        </div>
                    </div>
                    <div id="profitChart"></div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-lg-3 col-md-6 col-sm-6 mb-4">
        <div class="card">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div class="d-flex align-items-center gap-3">
                        <div class="avatar">
                            <span class="avatar-initial rounded-circle bg-label-danger"><i class="bx bxs-user-badge fs-4"></i></span>
                        </div>
                        <div class="card-info">
                            <h5 class="card-title mb-0 me-2">{{ $reject }}</h5>
                            <small class="text-muted">Reshudule</small>
                        </div>
                    </div>
                    <div id="expensesLineChart"></div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-xl-12 mt-4">

        <div class="card">

            <!-- Datatable go to last page -->
            <div class="col-xl-12 col-lg-12 col-sm-12  ">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h4 class="table-header">{{ __('Visitor Managment') }}</h4>
                    <div>
                        <a href="{{ route('enduservisit.create') }}" class="btn btn-primary">Create</a>
                    </div>
                </div>

                <div class="card-body">


                    <div class="table-responsive mb-4">
                        <table id="last-page-dt" class="table table-hover" style="width:100%">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Name</th>
                                    <th>Department</th>
                                    <th>print</th>

                                    <th></th>
                                </tr>
                            </thead>


                        </table>
                    </div>
                </div>

            </div>
        </div>
    </div>
</div>
@endsection
@push('stylesheets')
<!-- <link rel="stylesheet" href="{{ asset('assets/vendor/libs/apex-charts/apex-charts.css') }}" /> -->
@endpush



@push('scripts')
<script src="{{ asset('assets/vendor/libs/apex-charts/apexcharts.js') }}"></script>
<script src="{{ asset('assets/js/cards-statistics.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables/jquery.dataTables.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-bs5/datatables-bootstrap5.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-responsive/datatables.responsive.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/moment/moment.js') }}"></script>

<script>
    $(document).ready(function() {

        $('#last-page-dt').DataTable({
            "pagingType": "full_numbers",
            "language": {
                "paginate": {
                    "first": "<i class='las la-angle-double-left'></i>",
                    "previous": "<i class='las la-angle-left'></i>",
                    "next": "<i class='las la-angle-right'></i>",
                    "last": "<i class='las la-angle-double-right'></i>"
                }
            },
            "lengthMenu": [7, 14, 21, 28],
            "pageLength": 7,
            "ajax": "{{ route('visit.index') }}",
            "processing": true,
            "serverSide": true,
            "columns": [

                {
                    data: 'user',
                    name: 'user.name',
                    orderable: false,
                    render: function(data, type, row) {
                        let profile = "";
                        if (data?.profile_image_url) {
                            profile = '<img src="' + data?.profile_image_url +
                                '" class = "me-3 rounded" width = "40"  alt = "' + data?.name +
                                '" >';
                        }
                        return profile + '' + data?.name;
                    }
                },

                {
                    data: 'user.cnic',
                    orderable: false,
                },


                {
                    data: 'visit_to_name',
                    orderable: false,
                    searchable: false,
                },
                {
                    data: 'purpose',
                    orderable: false,
                },
                {
                    data: 'visiting_date',
                    orderable: false,
                },
                {
                    data: 'visiting_time',
                    orderable: false,
                    render: function(data, type, row) {
                        return moment().format('hh:mm a');
                    }
                },




                {
                    data: null,
                    orderable: false,

                }

            ],



        });





    });
</script>
@endpush