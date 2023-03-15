@extends('layouts.' . config('vms.active_layout'))
@php $app_id = config('vms.app_id') @endphp

@section('title', 'Visitor')
@push('stylesheets')
<link rel="stylesheet" href="{{ asset('assets/vendor/libs/datatables-bs5/datatables.bootstrap5.css') }}" />
<link rel="stylesheet" href="{{ asset('assets/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.css') }}" />
@endpush

@section('content')

<div class="layout-top-spacing mb-2">
    <div class="col-md-12">
        <div class="row">
            <div class="container p-0">
                <div class="row date-table-container">

                    <!-- Datatable go to last page -->
                    <div class="col-xl-12 col-lg-12 col-sm-12  card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5 class="card-title mb-0">{{ $title }}</h5>
                            <div>
                                <a href="{{ route('visitors.create') }}" class="btn btn-primary">Create</a>
                            </div>
                        </div>
                        <div class="card-body">



                            <div class="table-responsive mb-4">

                                <table id="last-page-dt" class="table border-top">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Name</th>
                                            <th>Cnic</th>
                                            <th>purpose</th>
                                            <th>Department</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>


                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Modal -->


        <div class="modal" tabindex="-1" id="myModal" role="dialog">
            <div class="modal-dialog modal-dialog-centered" role="document">
                <div class="modal-content ">
                    <div class="modal-header">
                        <h5 class="modal-title" id="exampleModalCenterTitle">Visitor Details</h5>

                    </div>
                    <div class="modal-body">
                        <form id="modalSubmit">
                            <input type="hidden" name="id" id="visitor_id" />

                            <div class="form-group">
                                <select class="form-control" id="status" name="status">
                                    <option selected>Open this select </option>
                                    <option value="3">Accept</option>
                                    <option value="4">Reject</option>
                                </select>
                            </div>

                            <div class="form-group" id="rejected_reason" style="display:none;">
                                <input type="text" class="form-control mt-2" placeholder="Enter Rejecting Reason" name="rejected_reason">
                            </div>


                            <div class="row m-0 p-0 mt-2 ">
                                <input type="time" class="form-control col-md-6" id="Mtime" name="visiting_time">
                                <input type="date" id="start" class="form-control col-md-6 px-1 " id="Mdate" name="visiting_date" min="2023-01-01">
                            </div>

                            <div class="form-group float-right pt-2">
                                <button type="submit" class="btn btn-primary btn-sm">Submit</button>
                                <button type="button" class="btn btn-danger btn-sm" id="Modelcancel">Cancel</button>
                            </div>
                        </form>
                    </div>

                </div>
            </div>
        </div>



    </div>
</div>
<!-- Main Body Ends -->
<!-- Button trigger modal -->



@extends('vms::visitor/modal');

@endsection

@push('scripts')
<script src="{{ asset('assets/vendor/libs/datatables/jquery.dataTables.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-bs5/datatables-bootstrap5.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-responsive/datatables.responsive.js') }}"></script>
<script src="{{ asset('assets/vendor/libs/datatables-responsive-bs5/responsive.bootstrap5.js') }}"></script>



<script>
    $(document).ready(function() {

        var params = '';
        var i = 0;
        window.location.search.replace(/[?&]+([^=&]+)=([^&]*)/gi, function(str, key, value) {
            if (i == 0) {
                params += [key] + '=' + value;
            } else {
                params += '&' + [key] + '=' + value;
            }
            i++;
        });
        if (params != '') {
            var url = "{{ route('visitors.index') }}?" + params;
        } else {
            var url = "{{ route('visitors.index') }}";
        }

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
            "ajax": url,
            "processing": true,
            "serverSide": true,
            "columns": [{
                    data: 'id',
                },
                {
                    data: 'user.name',
                    name: 'user.name',
                    orderable: false,
                },

                {
                    data: 'user.cnic',
                    orderable: false,
                },
                {
                    data: 'purpose',
                    orderable: false,
                },
                {
                    data: 'department_name',
                    orderable: false,
                    visible: "{{ Auth::user()->hasRole('Department') ? false : true }}"
                },

                // {
                //     data: null,
                //     orderable: false,

                //     render: function(data, type, row) {
                //         var editUrl = "{{ route('visitor.print', ':id') }}";
                //         editUrl = editUrl.replace(':id', data.id);
                //         isVisistor = "{{ Auth::user()->hasRole('visitor') ? true : 0 }}";
                //         let verificationButton = data.status == 2 ?
                //             "{!! Auth::user()->hasRole('Department') ? '<button class=\"btn btn-warning btn-sm modalAction \"  data-model=" +
                //             encodeURIComponent(JSON.stringify(data)) +
                //             "><i class=\"las la-check la-2x\" ></i></button>':''!! }" : '';
                //         let printBtn = "<a class=\"btn btn-primary btn-sm\"  href=\"" +
                //             editUrl + "\"><i class=\"las la-print la-2x\"></i></a>";
                //         let printbutton = isVisistor == 1 ? data.status == 3 ? printBtn : '' :
                //             printBtn;
                //         return printbutton + verificationButton;
                //     }

                // },



                {
                    data: null,
                    orderable: false,
                    render: function(data, type, row) {

                        return "<button class = \"btn btn-warning btn-sm showDetails\"  data-model=" +
                            encodeURIComponent(JSON.stringify(data)) +
                            ">View</button>"
                    }
                }

            ],



        });





        $("#Modelcancel").on('click', function() {
            $("#myModal").modal('hide');
        });


        $(document).on('click', '.modalAction', function() {
    // getting current Object 
            let modelData = $(this).attr("data-model");
            modelData = JSON.parse(decodeURIComponent(modelData));
            // console.log(modelData.user.name);
            $("#Mtime").val(modelData?.visiting_time);
            $("#Mdate").val(modelData?.visiting_date);
            var today = moment().format('dd/mm/yyyy');
            $('#Mdate').val(today);
            $("#visitor_id").val(modelData?.id);

            $("#myModal").modal("show");

        });
    });
</script>
@endpush